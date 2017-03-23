//! Authentication token structs, and methods
//!
//! This module provides the `Token` struct which encapsulates a JSON Web Token or `JWT`.
//! Clients will pass the encapsulated JWT to services that require it. The JWT should be considered opaque
//! to clients. The `Token` struct contains enough information for the client to act on, including expiry times.
use std::error;
use std::fmt;
use std::io::Cursor;
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;

use chrono::{self, DateTime, UTC};
use jwt::{self, jws};
use rocket::http::{ContentType, Status};
use rocket::response::{Response, Responder};
use serde::{Serialize, Deserialize};
use serde_json;
use uuid::{self, Uuid};

/// Token errors
#[derive(Debug)]
pub enum Error {
    /// Raised when attempting to encode an already encoded token
    TokenAlreadyEncoded,
    /// Raised when attempting to decode an already decoded token
    TokenAlreadyDecoded,
    /// Raised when attempting to use a decoded token when an encoded one is expected
    TokenNotEncoded,
    /// Raised when attempting to use an encoded token when an decoded one is expected
    TokenNotDecoded,
    /// Raised when the service requested is not in the list of intended audiences
    InvalidService,

    /// Errors during token encoding/decoding
    JWTError(jwt::errors::Error),
    /// Errors during token serialization
    TokenSerializationError(serde_json::Error),
}

impl_from_error!(jwt::errors::Error, Error::JWTError);
impl_from_error!(serde_json::Error, Error::TokenSerializationError);

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::TokenAlreadyEncoded => "Token is already encoded",
            Error::TokenAlreadyDecoded => "Token is already decoded",
            Error::TokenNotEncoded => "Token is not encoded and cannot be used in this context",
            Error::TokenNotDecoded => "Token is not decoded and cannot be used in this context",
            Error::InvalidService => "Service requested is not in the list of intended audiences",
            Error::JWTError(ref e) => e.description(),
            Error::TokenSerializationError(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::JWTError(ref e) => Some(e as &error::Error),
            Error::TokenSerializationError(ref e) => Some(e as &error::Error),
            _ => Some(self as &error::Error),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::JWTError(ref e) => fmt::Display::fmt(e, f),
            Error::TokenSerializationError(ref e) => fmt::Display::fmt(e, f),
            _ => write!(f, "{}", error::Error::description(self)),
        }
    }
}

impl<'r> Responder<'r> for Error {
    fn respond(self) -> Result<Response<'r>, Status> {
        error_!("Token Error: {:?}", self);
        match self {
            Error::InvalidService => Err(Status::Forbidden),
            _ => Err(Status::InternalServerError),
        }
    }
}

/// Token configuration. Usually deserialized as part of [`rowdy::Configuration`] from JSON for use.
///
///
/// # Examples
/// This is a standard JSON serialized example.
///
/// ```json
/// {
///     "issuer": "https://www.acme.com",
///     "allowed_origins": ["https://www.example.com", "https://www.foobar.com"],
///     "audience": ["https://www.example.com", "https://www.foobar.com"],
///     "signature_algorithm": "RS256",
///     "secret": {
///                 "rsa_private": "test/fixtures/rsa_private_key.der",
///                 "rsa_public": "test/fixtures/rsa_public_key.der"
///                },
///     "expiry_duration": 86400
/// }
/// ```
///
/// ```
/// extern crate rowdy;
/// extern crate serde_json;
///
/// use rowdy::token::Configuration;
///
/// # fn main() {
/// let json = r#"{
///     "issuer": "https://www.acme.com",
///     "allowed_origins": ["https://www.example.com", "https://www.foobar.com"],
///     "audience": ["https://www.example.com", "https://www.foobar.com"],
///     "signature_algorithm": "RS256",
///     "secret": {
///                 "rsa_private": "test/fixtures/rsa_private_key.der",
///                 "rsa_public": "test/fixtures/rsa_public_key.der"
///                },
///     "expiry_duration": 86400
/// }"#;
/// let deserialized: Configuration = serde_json::from_str(json).unwrap();
/// # }
/// ```
///
/// Variations for the fields `allowed_origins`, `audience` and `secret` exist. Refer to their type documentation for
/// examples.
#[derive(Serialize, Deserialize, Debug)]
pub struct Configuration {
    /// The issuer of the token. Usually the URI of the authentication server.
    /// The issuer URI will also be used in the UUID generation of the tokens, and is also the `realm` for
    /// authentication purposes.
    pub issuer: String,
    /// Origins that are allowed to issue CORS request. This is needed for browser
    /// access to the authentication server, but tools like `curl` do not obey nor enforce the CORS convention.
    ///
    /// This enum (de)serialized as an [untagged](https://serde.rs/enum-representations.html) enum variant.
    ///
    /// See [`cors::AllowedOrigins`] for serialization examples.
    pub allowed_origins: ::cors::AllowedOrigins,
    /// The audience intended for your tokens. The `service` request paremeter will be validated against this
    pub audience: jwt::SingleOrMultiple<jwt::StringOrUri>,
    /// Defaults to `none`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<jws::Algorithm>,
    /// Secrets for use in signing and encrypting a JWT.
    /// This enum (de)serialized as an [untagged](https://serde.rs/enum-representations.html) enum variant.
    /// Defaults to `None`.
    ///
    /// See [`token::Secret`] for serialization examples
    #[serde(default)]
    pub secret: Secret,
    /// Expiry duration of tokens, in seconds. Defaults to 24 hours when deserialized and left unfilled
    #[serde(with = "::serde_custom::duration", default = "Configuration::default_expiry_duration")]
    pub expiry_duration: Duration,
}
const DEFAULT_EXPIRY_DURATION: u64 = 86400;
impl Configuration {
    fn default_expiry_duration() -> Duration {
        Duration::from_secs(DEFAULT_EXPIRY_DURATION)
    }
}

/// Private claims that will be included in the JWT embedded. Currently, an empty shell.
#[derive(Default, Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct PrivateClaim {}

/// A token that will be serialized into JSON and passed to clients. This encapsulates a JSON Web Token or `JWT`.
/// Clients will pass the encapsulated JWT to services that require it. The JWT should be considered opaque
/// to clients. The `Token` struct contains enough information for the client to act on, including expiry times.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Token<T: Serialize + Deserialize> {
    /// Tne encapsulated JWT.
    pub token: jwt::JWT<T>,
    /// The duration from `issued_at` where the token will expire
    #[serde(with = "::serde_custom::duration")]
    pub expires_in: Duration,
    /// Time the token was issued at
    pub issued_at: DateTime<UTC>,
    /// Refresh token. Not used/implemented at the moment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>, // TODO
}

impl<T> Clone for Token<T>
    where T: Serialize + Deserialize + Clone
{
    fn clone(&self) -> Self {
        Token {
            token: self.token.clone(),
            expires_in: self.expires_in,
            issued_at: self.issued_at,
            refresh_token: self.refresh_token.clone(),
        }
    }
}

impl<T: Serialize + Deserialize> Token<T> {
    /// Convenience method to create a new token issued `Now`.
    pub fn new(header: jws::Header, claims_set: jwt::ClaimsSet<T>, expires_in: &Duration) -> Self {
        Token {
            token: jwt::JWT::new_decoded(header, claims_set),
            expires_in: *expires_in,
            issued_at: UTC::now(),
            refresh_token: None,
        }
    }

    fn make_uuid(uri: &str) -> Uuid {
        Uuid::new_v5(&uuid::NAMESPACE_URL, uri)
    }

    fn make_header(signature_algorithm: Option<jws::Algorithm>) -> jws::Header {
        jws::Header { algorithm: signature_algorithm.unwrap_or_else(|| jws::Algorithm::None), ..Default::default() }
    }

    fn make_registered_claims(subject: &str,
                              now: DateTime<UTC>,
                              expiry_duration: Duration,
                              issuer: &str,
                              audience: &jwt::SingleOrMultiple<jwt::StringOrUri>)
                              -> Result<jwt::RegisteredClaims, ::Error> {
        let expiry_duration = chrono::Duration::from_std(expiry_duration).map_err(|e| format!("{}", e))?;

        Ok(jwt::RegisteredClaims {
               issuer: Some(FromStr::from_str(issuer).map_err(Error::JWTError)?),
               subject: Some(FromStr::from_str(subject).map_err(Error::JWTError)?),
               audience: Some(audience.clone()),
               issued_at: Some(now.into()),
               not_before: Some(now.into()),
               expiry: Some((now + expiry_duration).into()),
               id: Some(Self::make_uuid(issuer).urn().to_string()),
           })
    }

    fn verify_service(config: &Configuration, service: &str) -> Result<(), Error> {
        if !config.audience.contains(&FromStr::from_str(service)?) {
            Err(Error::InvalidService)
        } else {
            Ok(())
        }
    }

    /// Internal token creation that allows for us to override the time `now`. For testing
    fn with_configuration_and_time(config: &Configuration,
                                   subject: &str,
                                   service: &str,
                                   private_claims: T,
                                   now: DateTime<UTC>)
                                   -> Result<Self, ::Error> {

        Self::verify_service(config, service)?;
        let header = Self::make_header(config.signature_algorithm);
        let registered_claims = Self::make_registered_claims(subject,
                                                             now,
                                                             config.expiry_duration,
                                                             &config.issuer,
                                                             &config.audience)?;
        let issued_at = registered_claims.issued_at.unwrap(); // we always set it, don't we?

        let token = Token::<T> {
            token: jwt::JWT::new_decoded(header,
                                         jwt::ClaimsSet::<T> {
                                             private: private_claims,
                                             registered: registered_claims,
                                         }),
            expires_in: config.expiry_duration,
            issued_at: *issued_at.deref(),
            refresh_token: None,
        };
        Ok(token)
    }

    /// Based on the configuration, make a token for the subject, along with some private claims.
    pub fn with_configuration(config: &Configuration,
                              subject: &str,
                              service: &str,
                              private_claims: T)
                              -> Result<Self, ::Error> {
        Self::with_configuration_and_time(config, subject, service, private_claims, UTC::now())
    }

    /// Consumes self and encode the embedded JWT with signature.
    /// If the JWT is already encoded, this returns an error
    pub fn encode(mut self, secret: jws::Secret) -> Result<Self, Error> {
        match self.token {
            jwt::JWT::Encoded(_) => Err(Error::TokenAlreadyEncoded),
            jwt @ jwt::JWT::Decoded { .. } => {
                self.token = jwt.into_encoded(secret)?;
                Ok(self)
            }
        }
    }

    /// Consumes self and decode the embedded JWT with signature verification
    /// If the JWT is already decoded, this returns an error
    pub fn decode(mut self, secret: jws::Secret, algorithm: jws::Algorithm) -> Result<Self, Error> {
        match self.token {
            jwt @ jwt::JWT::Encoded(_) => {
                self.token = jwt.into_decoded(secret, algorithm)?;
                Ok(self)
            }
            jwt::JWT::Decoded { .. } => Err(Error::TokenAlreadyDecoded),
        }
    }

    fn serialize_and_respond(self) -> Result<String, Error> {
        if let jwt::JWT::Decoded { .. } = self.token {
            Err(Error::TokenNotEncoded)?
        }
        let serialized = serde_json::to_string(&self)?;
        Ok(serialized)
    }

    /// Returns whether the wrapped token is decoded
    pub fn is_decoded(&self) -> bool {
        match self.token {
            jwt::JWT::Encoded(_) => false,
            jwt::JWT::Decoded { .. } => true,
        }
    }

    /// Returns whether the wrapped token is encoded
    pub fn is_encoded(&self) -> bool {
        !self.is_decoded()
    }

    /// Convenience function to extract the registered claims from a decoded token
    pub fn registered_claims(&self) -> Result<&jwt::RegisteredClaims, ::Error> {
        match self.token {
            jwt::JWT::Encoded(_) => Err(Error::TokenNotDecoded)?,
            ref jwt @ jwt::JWT::Decoded { .. } => {
                Ok(match_extract!(*jwt,
                                 jwt::JWT::Decoded {
                                     claims_set: jwt::ClaimsSet { ref registered, .. },
                                     ..
                                 },
                                 registered)?)
            }
        }
    }

    /// Conveneince function to extract the private claims from a decoded token
    pub fn private_claims(&self) -> Result<&T, ::Error> {
        match self.token {
            jwt::JWT::Encoded(_) => Err(Error::TokenNotDecoded)?,
            ref jwt @ jwt::JWT::Decoded { .. } => {
                Ok(match_extract!(*jwt,
                                 jwt::JWT::Decoded {
                                     claims_set: jwt::ClaimsSet { ref private, .. },
                                     ..
                                 },
                                 private)?)
            }
        }
    }

    /// Convenience function to extract the headers from a decoded token
    pub fn header(&self) -> Result<&jwt::jws::Header, ::Error> {
        match self.token {
            jwt::JWT::Encoded(_) => Err(Error::TokenNotDecoded)?,
            ref jwt @ jwt::JWT::Decoded { .. } => {
                Ok(match_extract!(*jwt,
                                 jwt::JWT::Decoded {
                                     ref header,
                                     ..
                                 },
                                 header)?)
            }
        }
    }

    /// Convenience mthod to extract the encoded token
    pub fn encoded_token(&self) -> Result<&str, ::Error> {
        match self.token {
            jwt::JWT::Decoded { .. } => Err(Error::TokenNotEncoded)?,
            jwt::JWT::Encoded(ref encoded) => Ok(encoded),
        }
    }
}

impl<'r, T: Serialize + Deserialize> Responder<'r> for Token<T> {
    fn respond(self) -> Result<Response<'r>, Status> {
        match self.serialize_and_respond() {
            Ok(serialized) => Response::build().header(ContentType::JSON).sized_body(Cursor::new(serialized)).ok(),
            Err(e) => Err::<String, Error>(e).respond(),
        }
    }
}

/// Secrets for use in signing and encrypting a JWT.
/// This enum (de)serialized as an [untagged](https://serde.rs/enum-representations.html) enum variant.
/// Defaults to `None`.
///
/// # Serialization Examples
/// ## No secret
/// ```json
/// {
///     "secret": null
/// }
/// ```
/// ```
/// extern crate rowdy;
/// #[macro_use]
/// extern crate serde_derive;
/// extern crate serde_json;
///
/// use rowdy::token;
///
/// # fn main() {
/// #[derive(Serialize, Deserialize)]
/// struct Test {
///     secret: token::Secret
/// }
///
/// let json = r#"{ "secret": null }"#;
/// let deserialized: Test = serde_json::from_str(json).unwrap();
/// # }
/// ```
/// ## HMAC secret string
/// ```json
/// {
///     "secret": "some_secret_string"
/// }
/// ```
/// ```
/// extern crate rowdy;
/// #[macro_use]
/// extern crate serde_derive;
/// extern crate serde_json;
///
/// use rowdy::token;
///
/// # fn main() {
/// #[derive(Serialize, Deserialize)]
/// struct Test {
///     secret: token::Secret
/// }
///
/// let json = r#"{ "secret": "some_secret_string" }"#;
/// let deserialized: Test = serde_json::from_str(json).unwrap();
/// # }
/// ```
/// ## RSA Key pair
/// ```json
/// {
///     "secret": { "rsa_private": "private.der", "rsa_public": "public.der" }
/// }
/// ```
/// ```
/// extern crate rowdy;
/// #[macro_use]
/// extern crate serde_derive;
/// extern crate serde_json;
///
/// use rowdy::token;
///
/// # fn main() {
/// #[derive(Serialize, Deserialize)]
/// struct Test {
///     secret: token::Secret
/// }
///
/// let json = r#"{ "secret": { "rsa_private": "private.der", "rsa_public": "public.der" } }"#;
/// let deserialized: Test = serde_json::from_str(json).unwrap();
/// # }
/// ```
// Note: A "smoke test"-ish of (de)serialization is tested in the documentation code above.
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Secret {
    /// No secret -- used when no signature or encryption is required.
    None,
    /// Secret for HMAC signing
    String(String),
    /// DER RSA Key pair.
    /// See [`jwt::jws::Secret`] for more details.
    RSAKeyPair {
        /// Path to DER encoded private key
        rsa_private: String,
        /// Path to DER encoded public key
        rsa_public: String,
    },
}

impl Default for Secret {
    fn default() -> Self {
        Secret::None
    }
}

impl Secret {
    /// Create a [`jws::Secret`] for the purpose of signing
    pub fn for_signing(&self) -> Result<jws::Secret, Error> {
        match *self {
            Secret::None => Ok(jws::Secret::None),
            Secret::String(ref secret) => Ok(jws::Secret::bytes_from_str(secret)),
            Secret::RSAKeyPair { ref rsa_private, .. } => Ok(jws::Secret::rsa_keypair_from_file(rsa_private)?),
        }
    }

    /// Create a [`jws::Secret`] for the purpose of verifying signatures
    pub fn for_verification(&self) -> Result<jws::Secret, Error> {
        match *self {
            Secret::None => Ok(jws::Secret::None),
            Secret::String(ref secret) => Ok(jws::Secret::bytes_from_str(secret)),
            Secret::RSAKeyPair { ref rsa_public, .. } => Ok(jws::Secret::public_key_from_file(rsa_public)?),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::default::Default;
    use std::time::Duration;

    use chrono::{DateTime, NaiveDateTime, UTC};
    use jwt;
    use serde_json;

    use super::*;

    #[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
    struct TestClaims {
        company: String,
        department: String,
    }

    impl Default for TestClaims {
        fn default() -> Self {
            TestClaims {
                company: "ACME".to_string(),
                department: "Toilet Cleaning".to_string(),
            }
        }
    }

    fn make_token() -> Token<TestClaims> {
        Token::new(jwt::jws::Header::default(),
                   jwt::ClaimsSet {
                       private: Default::default(),
                       registered: Default::default(),
                   },
                   &Duration::from_secs(120))
    }

    #[test]
    fn encoding_and_decoding_round_trip() {
        let token = make_token();
        let token = not_err!(token.encode(jwt::jws::Secret::bytes_from_str("secret")));
        assert!(token.is_encoded());

        let token = not_err!(token.decode(jwt::jws::Secret::bytes_from_str("secret"), Default::default()));
        let private = not_err!(token.private_claims());

        assert_eq!(*private, Default::default());
    }

    #[test]
    #[should_panic(expected = "TokenAlreadyEncoded")]
    fn panics_when_encoding_encoded() {
        let token = make_token();
        let token = not_err!(token.encode(jwt::jws::Secret::bytes_from_str("secret")));
        token.encode(jwt::jws::Secret::bytes_from_str("secret")).unwrap();
    }

    #[test]
    #[should_panic(expected = "TokenAlreadyDecoded")]
    fn panics_when_decoding_decoded() {
        let token = make_token();
        token.decode(jwt::jws::Secret::bytes_from_str("secret"),
                     Default::default())
            .unwrap();
    }

    #[test]
    fn token_serialization_smoke_test() {
        let expected_token = make_token();
        let token = not_err!(expected_token.clone().encode(jwt::jws::Secret::bytes_from_str("secret")));
        let serialized = not_err!(token.serialize_and_respond());

        let deserialized: Token<TestClaims> = not_err!(serde_json::from_str(&serialized));
        let actual_token =
            not_err!(deserialized.decode(jwt::jws::Secret::bytes_from_str("secret"), Default::default()));
        assert_eq!(expected_token, actual_token);
    }

    #[test]
    fn token_response_smoke_test() {
        use rocket::response::Responder;

        let expected_token = make_token();
        let token = not_err!(expected_token.clone().encode(jwt::jws::Secret::bytes_from_str("secret")));
        let mut response = not_err!(token.respond());

        assert_eq!(response.status(), Status::Ok);
        let body_str = not_none!(response.body().and_then(|body| body.into_string()));
        let deserialized: Token<TestClaims> = not_err!(serde_json::from_str(&body_str));
        let actual_token =
            not_err!(deserialized.decode(jwt::jws::Secret::bytes_from_str("secret"), Default::default()));
        assert_eq!(expected_token, actual_token);
    }

    #[test]
    fn secrets_are_transformed_for_signing_correctly() {
        let none = Secret::None;
        assert_matches_non_debug!(not_err!(none.for_signing()), jwt::jws::Secret::None);

        let string = Secret::String("secret".to_string());
        assert_matches_non_debug!(not_err!(string.for_signing()), jwt::jws::Secret::Bytes(_));

        let rsa = Secret::RSAKeyPair {
            rsa_private: "test/fixtures/rsa_private_key.der".to_string(),
            rsa_public: "test/fixtures/rsa_public_key.der".to_string(),
        };
        assert_matches_non_debug!(not_err!(rsa.for_signing()), jwt::jws::Secret::RSAKeyPair(_));
    }

    #[test]
    fn secrets_are_transformed_for_verification_correctly() {
        let none = Secret::None;
        assert_matches_non_debug!(not_err!(none.for_verification()), jwt::jws::Secret::None);

        let string = Secret::String("secret".to_string());
        assert_matches_non_debug!(not_err!(string.for_verification()), jwt::jws::Secret::Bytes(_));

        let rsa = Secret::RSAKeyPair {
            rsa_private: "test/fixtures/rsa_private_key.der".to_string(),
            rsa_public: "test/fixtures/rsa_public_key.der".to_string(),
        };
        assert_matches_non_debug!(not_err!(rsa.for_verification()), jwt::jws::Secret::PublicKey(_));
    }

    #[test]
    fn tokens_are_created_with_the_right_values() {
        let allowed_origins = ["https://www.example.com"];
        let (allowed_origins, _) = ::cors::AllowedOrigins::new_from_str_list(&allowed_origins);
        let configuration = Configuration {
            issuer: "https://www.acme.com".to_string(),
            allowed_origins: allowed_origins,
            audience: jwt::SingleOrMultiple::Single(FromStr::from_str("https://www.example.com/").unwrap()),
            signature_algorithm: Some(jwt::jws::Algorithm::HS512),
            secret: Secret::String("secret".to_string()),
            expiry_duration: Duration::from_secs(120),
        };

        let now = DateTime::<UTC>::from_utc(NaiveDateTime::from_timestamp(0, 0), UTC);
        let expected_expiry = now + chrono::Duration::from_std(Duration::from_secs(120)).unwrap();
        let token = not_err!(Token::<TestClaims>::with_configuration_and_time(&configuration,
                                                                              "Donald Trump",
                                                                              "https://www.example.com/",
                                                                              Default::default(),
                                                                              now));

        // Assert registered claims
        let registered = not_err!(token.registered_claims());

        assert_eq!(registered.issuer, Some(FromStr::from_str("https://www.acme.com").unwrap()));
        assert_eq!(registered.subject, Some(FromStr::from_str("Donald Trump").unwrap()));
        assert_eq!(registered.audience,
                   Some(jwt::SingleOrMultiple::Single(FromStr::from_str("https://www.example.com").unwrap())));
        assert_eq!(registered.issued_at, Some(now.into()));
        assert_eq!(registered.not_before, Some(now.into()));
        assert_eq!(registered.expiry, Some(expected_expiry.into()));

        // Assert private claims
        let private = not_err!(token.private_claims());
        assert_eq!(*private, Default::default());

        // Assert header
        let header = not_err!(token.header());
        assert_eq!(header.algorithm, jwt::jws::Algorithm::HS512);
    }

    #[test]
    #[should_panic(expected = "InvalidService")]
    fn validates_service_correctly() {
        let allowed_origins = ["https://www.example.com"];
        let (allowed_origins, _) = ::cors::AllowedOrigins::new_from_str_list(&allowed_origins);
        let configuration = Configuration {
            issuer: "https://www.acme.com".to_string(),
            allowed_origins: allowed_origins,
            audience: jwt::SingleOrMultiple::Single(FromStr::from_str("https://www.example.com/").unwrap()),
            signature_algorithm: Some(jwt::jws::Algorithm::HS512),
            secret: Secret::String("secret".to_string()),
            expiry_duration: Duration::from_secs(120),
        };

        let now = DateTime::<UTC>::from_utc(NaiveDateTime::from_timestamp(0, 0), UTC);
        Token::<TestClaims>::with_configuration_and_time(&configuration,
                                                         "Donald Trump",
                                                         "invalid",
                                                         Default::default(),
                                                         now)
                .unwrap();
    }
}
