//! Authentication token structs, and methods
//!
//! This module provides the `Token` struct which encapsulates a JSON Web Token or `JWT`.
//! Clients will pass the encapsulated JWT to services that require it. The JWT should be considered opaque
//! to clients. The `Token` struct contains enough information for the client to act on, including expiry times.
use std::collections::HashSet;
use std::borrow::Borrow;
use std::error;
use std::fmt;
use std::fs::File;
use std::io::{self, Cursor, Read};
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;

use cors;
use chrono::{self, DateTime, Utc};
use jwt::{self, jws, jwa, jwk};
use rocket::Request;
use rocket::http::{ContentType, Status, Method};
use rocket::response::{Response, Responder};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json;
use uuid::Uuid;

use {ByteSequence, JsonValue};

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
    /// Raised when attempting to perform an operation on the refresh token, but the refresh token is not present
    NoRefreshToken,
    /// Raised when attempting to encrypt and sign an already encrypted and signed refresh token
    RefreshTokenAlreadyEncrypted,
    /// Raised when attempting to decrypt and verify an already decrypted and verified refresh token
    RefreshTokenAlreadyDecrypted,
    /// Raised when attempting to use an encrypted refresh token when a decrypted one is expected
    RefreshTokenNotDecrypted,
    /// Raised when attempting to use an decrypted refresh token when a encrypted one is expected
    RefreshTokenNotEncrypted,
    /// Raised when the service requested is not in the list of intended audiences
    InvalidService,
    /// Raised when the issuer is invalid
    InvalidIssuer,
    /// Raised when the audience is invalid
    InvalidAudience,

    /// Generic Error
    GenericError(String),
    /// IO Error when reading keys from files
    IOError(io::Error),
    /// Errors during token encoding/decoding
    JWTError(jwt::errors::Error),
    /// Errors during token serialization
    TokenSerializationError(serde_json::Error),
}

impl_from_error!(jwt::errors::Error, Error::JWTError);
impl_from_error!(io::Error, Error::IOError);
impl_from_error!(serde_json::Error, Error::TokenSerializationError);
impl_from_error!(String, Error::GenericError);

impl<'a> From<&'a str> for Error {
    fn from(s: &'a str) -> Error {
        Error::GenericError(s.to_string())
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::TokenAlreadyEncoded => "Token is already encoded",
            Error::TokenAlreadyDecoded => "Token is already decoded",
            Error::TokenNotEncoded => "Token is not encoded and cannot be used in this context",
            Error::TokenNotDecoded => "Token is not decoded and cannot be used in this context",
            Error::NoRefreshToken => "Refresh token is not present",
            Error::RefreshTokenAlreadyEncrypted => "Refresh token is already encrypted and signed",
            Error::RefreshTokenAlreadyDecrypted => "Refresh token is already decrypted and verified",
            Error::RefreshTokenNotDecrypted => "Refresh token is not decrypted and cannot be used in this context",
            Error::RefreshTokenNotEncrypted => "Refresh token is not encrypted and cannot be used in this context",
            Error::InvalidService => "Service requested is not in the list of intended audiences",
            Error::InvalidIssuer => "The token has an invalid issuer",
            Error::InvalidAudience => "The token has invalid audience",
            Error::JWTError(ref e) => e.description(),
            Error::IOError(ref e) => e.description(),
            Error::TokenSerializationError(ref e) => e.description(),
            Error::GenericError(ref e) => e,
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::JWTError(ref e) => Some(e),
            Error::IOError(ref e) => Some(e),
            Error::TokenSerializationError(ref e) => Some(e),
            _ => Some(self),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::JWTError(ref e) => fmt::Display::fmt(e, f),
            Error::IOError(ref e) => fmt::Display::fmt(e, f),
            Error::TokenSerializationError(ref e) => fmt::Display::fmt(e, f),
            Error::GenericError(ref e) => fmt::Display::fmt(e, f),
            _ => write!(f, "{}", error::Error::description(self)),
        }
    }
}

impl<'r> Responder<'r> for Error {
    fn respond_to(self, _: &Request) -> Result<Response<'r>, Status> {
        error_!("Token Error: {:?}", self);
        match self {
            Error::InvalidService | Error::InvalidIssuer | Error::InvalidAudience => Err(Status::Forbidden),
            Error::JWTError(ref e) => {
                use jwt::errors::Error::*;

                let status = match *e {
                    ValidationError(_) |
                    JsonError(_) |
                    DecodeBase64(_) |
                    Utf8(_) |
                    UnspecifiedCryptographicError => Status::Unauthorized,
                    _ => Status::InternalServerError,
                };
                Err(status)
            }
            _ => Err(Status::InternalServerError),
        }
    }
}

fn make_uuid() -> Result<Uuid, Error> {
    use std::error::Error;
    use jwt::jwa::SecureRandom;

    let mut bytes = vec![0; 16];
    jwa::rng().fill(&mut bytes).map_err(
        |_| "Unable to generate UUID",
    )?;
    Ok(Uuid::from_bytes(&bytes).map_err(
        |e| e.description().to_string(),
    )?)
}

fn make_header(signature_algorithm: Option<jwa::SignatureAlgorithm>) -> jws::Header<jwt::Empty> {
    let registered = jws::RegisteredHeader {
        algorithm: signature_algorithm.unwrap_or_else(|| jwa::SignatureAlgorithm::None),
        ..Default::default()
    };
    jws::Header::from_registered_header(registered)
}

fn make_registered_claims(
    subject: &str,
    now: DateTime<Utc>,
    expiry_duration: Duration,
    issuer: &jwt::StringOrUri,
    audience: &jwt::SingleOrMultiple<jwt::StringOrUri>,
) -> Result<jwt::RegisteredClaims, ::Error> {
    let expiry_duration = chrono::Duration::from_std(expiry_duration).map_err(
        |e| e.to_string(),
    )?;

    Ok(jwt::RegisteredClaims {
        issuer: Some(issuer.clone()),
        subject: Some(FromStr::from_str(subject).map_err(Error::JWTError)?),
        audience: Some(audience.clone()),
        issued_at: Some(now.into()),
        not_before: Some(now.into()),
        expiry: Some((now + expiry_duration).into()),
        id: Some(make_uuid()?.urn().to_string()),
    })
}

/// Make a new JWS
#[cfg_attr(feature = "clippy_lints", allow(too_many_arguments))] // Internal function
fn make_token<P: Serialize + DeserializeOwned + 'static>(
    subject: &str,
    issuer: &jwt::StringOrUri,
    audience: &jwt::SingleOrMultiple<jwt::StringOrUri>,
    expiry_duration: Duration,
    private_claims: P,
    signature_algorithm: Option<jwa::SignatureAlgorithm>,
    now: DateTime<Utc>,
) -> Result<jwt::JWT<P, jwt::Empty>, ::Error> {
    let header = make_header(signature_algorithm);
    let registered_claims = make_registered_claims(subject, now, expiry_duration, issuer, audience)?;

    Ok(jwt::JWT::new_decoded(
        header,
        jwt::ClaimsSet::<P> {
            private: private_claims,
            registered: registered_claims,
        },
    ))
}

/// Verify that the service requested for is allowed in the configuration
fn verify_service(config: &Configuration, service: &str) -> Result<(), Error> {
    if !config.audience.contains(&FromStr::from_str(service)?) {
        Err(Error::InvalidService)
    } else {
        Ok(())
    }
}

/// Verify that the issuer is expected from the configuration
fn verify_issuer(config: &Configuration, issuer: &jwt::StringOrUri) -> Result<(), Error> {
    if *issuer == config.issuer {
        Ok(())
    } else {
        Err(Error::InvalidIssuer)
    }
}

/// Verify that the requested audience is a strict subset of the audience configured
fn verify_audience(config: &Configuration, audience: &jwt::SingleOrMultiple<jwt::StringOrUri>) -> Result<(), Error> {
    let allowed_audience: HashSet<jwt::StringOrUri> = config.audience.iter().cloned().collect();
    let audience: HashSet<jwt::StringOrUri> = audience.iter().cloned().collect();

    if audience.is_subset(&allowed_audience) {
        Ok(())
    } else {
        Err(Error::InvalidAudience)
    }
}

/// A wrapper around `cors::Options` for options specific to the token retrival route
pub type TokenGetterCorsOptions = cors::Cors;

const TOKEN_GETTER_METHODS: &[Method] = &[Method::Get];
const TOKEN_GETTER_HEADERS: &[&str] = &[
    "Authorization",
    "Accept",
    "Accept-Language",
    "Content-Language",
    "Content-Type",
    "Origin",
];

/// Token configuration. Usually deserialized as part of [`rowdy::Configuration`] from JSON for use.
///
///
/// # Examples
/// This is a standard JSON serialized example.
///
/// ```json
/// {
///     "issuer": "https://www.acme.com",
///     "allowed_origins": { "Some": ["https://www.example.com", "https://www.foobar.com"] },
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
///     "allowed_origins": { "Some": ["https://www.example.com", "https://www.foobar.com"] },
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
    pub issuer: jwt::StringOrUri,
    /// Origins that are allowed to issue CORS request. This is needed for browser
    /// access to the authentication server, but tools like `curl` do not obey nor enforce the CORS convention.
    ///
    pub allowed_origins: cors::AllOrSome<HashSet<cors::headers::Url>>,
    /// The audience intended for your tokens. The `service` request paremeter will be validated against this
    pub audience: jwt::SingleOrMultiple<jwt::StringOrUri>,
    /// Defaults to `none`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<jwa::SignatureAlgorithm>,
    /// Secrets for use in signing a JWT.
    /// This enum (de)serialized as an [untagged](https://serde.rs/enum-representations.html) enum variant.
    /// Defaults to `None`.
    ///
    /// See [`token::Secret`] for serialization examples
    #[serde(default)]
    pub secret: Secret,
    /// Expiry duration of tokens, in seconds. Defaults to 24 hours when deserialized and left unfilled
    #[serde(with = "::serde_custom::duration", default = "Configuration::default_expiry_duration")]
    pub expiry_duration: Duration,
    /// Customise refresh token options. Set to `None` to disable refresh tokens
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refresh_token: Option<RefreshTokenConfiguration>,
}

const DEFAULT_EXPIRY_DURATION: u64 = 86400;
impl Configuration {
    fn default_expiry_duration() -> Duration {
        Duration::from_secs(DEFAULT_EXPIRY_DURATION)
    }

    /// Return a new CORS Option
    pub(crate) fn cors_option(&self) -> TokenGetterCorsOptions {
        cors::Cors {
            allowed_origins: self.allowed_origins.clone(),
            allowed_methods: TOKEN_GETTER_METHODS
                .iter()
                .cloned()
                .map(From::from)
                .collect(),
            allowed_headers: cors::AllOrSome::Some(
                TOKEN_GETTER_HEADERS
                    .iter()
                    .map(|s| s.to_string().into())
                    .collect(),
            ),
            allow_credentials: true,
            ..Default::default()
        }
    }

    /// Returns whether refresh tokens are enabled
    pub fn refresh_token_enabled(&self) -> bool {
        self.refresh_token.is_some()
    }

    /// Convenience function to return a reference to the Refresh Token configuration.
    ///
    /// # Panics
    /// Panics if refresh token is not enabled
    pub fn refresh_token(&self) -> &RefreshTokenConfiguration {
        self.refresh_token.as_ref().unwrap()
    }

    /// Prepare the keys for use with various cryptographic operations
    pub fn keys(&self) -> Result<Keys, Error> {
        let (encryption, decryption) = if self.refresh_token_enabled() {
            let key = &self.refresh_token().key;
            (Some(key.for_encryption()?), Some(key.for_decryption()?))
        } else {
            (None, None)
        };

        Ok(Keys {
            signing: self.secret.for_signing()?,
            signature_verification: self.secret.for_verification()?,
            encryption: encryption,
            decryption: decryption,
        })
    }
}

/// Configuration for Refresh Tokens
///
/// Refresh Tokens are encrypted JWS, signed with the same algorithm as access tokens. There are two algorithms used.
///
/// A content encryption algorithm is used to encrypt the payload of the token, and provided some integrity protection.
/// The algorithm used is symmetric. The list of supported algorithm can be found
/// [here](https://lawliet89.github.io/biscuit/biscuit/jwa/enum.ContentEncryptionAlgorithm.html). The key used to
/// encrypt the content is called the Content Encryption Key (CEK).
///
/// Another algorithm is employed to determine and/or encrypt the CEK. The list of supported algorithms
/// can be found [here](https://lawliet89.github.io/biscuit/biscuit/jwa/enum.KeyManagementAlgorithm.html).
#[derive(Serialize, Deserialize, Debug)]
pub struct RefreshTokenConfiguration {
    /// Algorithm used to determine and/or encrypt the CEK
    pub cek_algorithm: jwa::KeyManagementAlgorithm,

    /// Algorithm used to encrypt the content using the CEK
    pub enc_algorithm: jwa::ContentEncryptionAlgorithm,

    /// Key used in determining the CEK, or directly encrypt the content depending on the `cek_algorithm`
    pub key: Secret,

    /// Expiry duration of refresh tokens, in seconds. Defaults to 24 hours when deserialized and left unfilled
    #[serde(with = "::serde_custom::duration", default = "Configuration::default_expiry_duration")]
    pub expiry_duration: Duration,
}

/// Private claims that will be included in the JWT.
pub type PrivateClaim = JsonValue;

/// Convenient typedef for the type of the Refresh Token Payload. This is a signed JWS which contains a JWT Claims set.
pub type RefreshTokenPayload = jwt::JWT<JsonValue, jwt::Empty>;

/// Convenient typedef for the type of the encrypted JWE wrapping `RefreshTokenPayload`. This is a JWE which contains
/// a JWS that contains a JWT Claims set.
pub type RefreshTokenJWE = jwt::jwe::Compact<RefreshTokenPayload, jwt::Empty>;

/// A Refresh Token containing the payload (called refresh payload) used by an authenticator to issue new access
/// tokens without needing the user to re-authenticate.
///
/// Internally, this is a newtype struct wrapping an encrypted JWE containing the `RefreshTokenPayload`. In other
/// words, this is an encrypted token (JWE) containing a payload. The payload is a signed token (JWS) which contains
/// a set of values (JWT Claims Set).
///
/// Usually, the semantics and inner workings of the refresh token is, and should be, opaque to any
/// user. Thus, some of the methods to manipulate the inner details of the refresh tokens are not public.
///
/// This struct is serialized and deserialized to a string, which is the
/// [Compact serialization of a JWE](https://tools.ietf.org/html/rfc7516#section-3.1).
///
/// Before you can serialize the struct, you will need to call `encrypt` to first sign the embedded JWS, and then
/// encrypt it. If you do not do so, `serde` will refuse to serialize.
///
/// Conversely, only an encrypted token can be deserialized. `serde` will refuse to deserialize a decrypted token
/// similarly. You will need to call `decrypt` to decrypt the deserialized token.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct RefreshToken(RefreshTokenJWE);

impl RefreshToken {
    #[cfg_attr(feature = "clippy_lints", allow(too_many_arguments))] // Internal function
    fn new_decrypted(
        subject: &str,
        issuer: &jwt::StringOrUri,
        audience: &jwt::SingleOrMultiple<jwt::StringOrUri>,
        expiry_duration: Duration,
        payload: &JsonValue,
        signature_algorithm: Option<jwa::SignatureAlgorithm>,
        cek_algorithm: jwa::KeyManagementAlgorithm,
        enc_algorithm: jwa::ContentEncryptionAlgorithm,
        now: DateTime<Utc>,
    ) -> Result<Self, ::Error> {

        // First, make a token
        let token = make_token(
            subject,
            issuer,
            audience,
            expiry_duration,
            payload.clone(),
            signature_algorithm,
            now,
        )?;
        // Wrap it in a JWE
        let jwe = jwt::JWE::new_decrypted(
            From::from(jwt::jwe::RegisteredHeader {
                cek_algorithm: cek_algorithm,
                enc_algorithm: enc_algorithm,
                media_type: Some("JOSE".to_string()),
                content_type: Some("JOSE".to_string()),
                ..Default::default()
            }),
            token,
        );
        Ok(RefreshToken(jwe))
    }

    /// Create a new decrypted struct based on the Base64 encoded token string
    pub fn new_encrypted(token: &str) -> Self {
        RefreshToken(jwt::JWE::new_encrypted(token))
    }

    /// Unwrap and consumes self, producing the wrapped JWE. You generally should not, and do not need to call this.
    pub fn unwrap(self) -> RefreshTokenJWE {
        self.0
    }

    /// Returns whether the refresh token is already encrypted and signed
    pub fn encrypted(&self) -> bool {
        match *self.borrow() {
            jwt::jwe::Compact::Decrypted { .. } => false,
            jwt::jwe::Compact::Encrypted(_) => true,
        }
    }

    /// Returns whether the refresh token is already decrypted and verified
    pub fn decrypted(&self) -> bool {
        !self.encrypted()
    }

    /// Consumes self, and sign and encrypt the refresh token.
    /// If the Refresh Token is already encrypted, this will return an error
    pub fn encrypt(self, secret: &jws::Secret, key: &jwk::JWK<jwt::Empty>) -> Result<Self, Error> {
        if self.encrypted() {
            Err(Error::RefreshTokenAlreadyEncrypted)?
        }

        let (header, jws) = self.unwrap().unwrap_decrypted();
        let jws = jws.into_encoded(secret)?;

        let jwe = jwt::JWE::new_decrypted(header, jws);
        let jwe = jwe.into_encrypted(key)?;

        Ok(From::from(jwe))
    }

    /// Consumes self, and decrypt and verify the signature of the refresh token
    /// If the refresh token is already decrypted, this will return an error
    pub fn decrypt(
        self,
        secret: &jws::Secret,
        key: &jwk::JWK<jwt::Empty>,
        signing_algorithm: jwa::SignatureAlgorithm,
        cek_algorithm: jwa::KeyManagementAlgorithm,
        enc_algorithm: jwa::ContentEncryptionAlgorithm,
    ) -> Result<Self, Error> {
        if self.decrypted() {
            Err(Error::RefreshTokenAlreadyDecrypted)?
        }

        let jwe = self.unwrap();
        let jwe = jwe.into_decrypted(key, cek_algorithm, enc_algorithm)?;

        let (header, jws) = jwe.unwrap_decrypted();
        let jws = jws.into_decoded(secret, signing_algorithm)?;

        let jwe = jwt::JWE::new_decrypted(header, jws);

        Ok(From::from(jwe))
    }

    /// Retrieve a reference to the decrypted claims set
    fn claims_set(&self) -> Result<&jwt::ClaimsSet<JsonValue>, Error> {
        if !self.decrypted() {
            Err(Error::RefreshTokenNotDecrypted)?;
        }

        Ok(self.0.payload()?.payload()?)
    }

    /// Retrieve a reference to the decrypted payload
    pub fn payload(&self) -> Result<&JsonValue, Error> {
        Ok(&self.claims_set()?.private)
    }

    /// Validate the times and claims of the refresh token
    pub fn validate(
        &self,
        service: &str,
        config: &Configuration,
        options: Option<jwt::TemporalValidationOptions>,
    ) -> Result<(), Error> {
        use std::str::FromStr;

        let options = options.or_else(|| {
            Some(jwt::TemporalValidationOptions {
                issued_at_required: true,
                not_before_required: true,
                expiry_required: true,
                ..Default::default()
            })
        });

        let claims_set = self.claims_set()?;
        let issuer = claims_set.registered.issuer.as_ref().ok_or_else(
            || Error::InvalidIssuer,
        )?;
        let audience = claims_set.registered.audience.as_ref().ok_or_else(|| {
            Error::InvalidAudience
        })?;

        verify_service(config, service)
            .and_then(|_| if audience.contains(&FromStr::from_str(service)?) {
                Ok(())
            } else {
                Err(Error::InvalidAudience)
            })
            .and_then(|_| verify_audience(config, audience))
            .and_then(|_| verify_issuer(config, issuer))
            .and_then(|_| {
                claims_set.registered.validate_times(options).map_err(|e| {
                    Error::JWTError(jwt::errors::Error::ValidationError(e))
                })
            })
    }

    /// Convenience function to convert a decrypted payload to string
    pub fn to_string(&self) -> Result<String, Error> {
        Ok(
            self.0
                .encrypted()
                .map_err(|_| Error::RefreshTokenNotEncrypted)?
                .to_string(),
        )
    }
}

impl Borrow<RefreshTokenJWE> for RefreshToken {
    fn borrow(&self) -> &RefreshTokenJWE {
        &self.0
    }
}

impl From<RefreshTokenJWE> for RefreshToken {
    fn from(value: RefreshTokenJWE) -> Self {
        RefreshToken(value)
    }
}

/// A token that will be serialized into JSON and passed to clients. This encapsulates a JSON Web Token or `JWT`.
/// Clients will pass the encapsulated JWT to services that require it. The JWT should be considered opaque
/// to clients. The `Token` struct contains enough information for the client to act on, including expiry times.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Token<T> {
    /// Tne encapsulated JWT.
    pub token: jwt::JWT<T, jwt::Empty>,
    /// The duration from `issued_at` where the token will expire
    #[serde(with = "::serde_custom::duration")]
    pub expires_in: Duration,
    /// Time the token was issued at
    pub issued_at: DateTime<Utc>,
    /// Refresh token, if enabled and requested for
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<RefreshToken>,
}

impl<T> Clone for Token<T>
where
    T: Serialize + DeserializeOwned + Clone,
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

impl<T: Serialize + DeserializeOwned + 'static> Token<T> {
    /// Internal token creation that allows for us to override the time `now`. For testing
    fn with_configuration_and_time(
        config: &Configuration,
        subject: &str,
        service: &str,
        private_claims: T,
        refresh_token_payload: Option<&JsonValue>,
        now: DateTime<Utc>,
    ) -> Result<Self, ::Error> {

        verify_service(config, service)?;

        let access_token = make_token(
            subject,
            &config.issuer,
            &config.audience,
            config.expiry_duration,
            private_claims,
            config.signature_algorithm,
            now,
        )?;
        let refresh_token = match config.refresh_token {
            None => None,
            Some(ref refresh_token_config) => {
                match refresh_token_payload {
                    Some(payload) => {
                        Some(RefreshToken::new_decrypted(
                            subject,
                            &config.issuer,
                            &config.audience,
                            refresh_token_config.expiry_duration,
                            payload,
                            config.signature_algorithm,
                            refresh_token_config.cek_algorithm,
                            refresh_token_config.enc_algorithm,
                            now,
                        )?)
                    }
                    None => None,
                }
            }
        };

        // Safe to unwrap
        let issued_at = access_token
            .payload()
            .unwrap()
            .registered
            .issued_at
            .unwrap();

        let token = Token::<T> {
            token: access_token,
            expires_in: config.expiry_duration,
            issued_at: *issued_at.deref(),
            refresh_token: refresh_token,
        };
        Ok(token)
    }

    /// Based on the configuration, make a token for the subject, along with some private claims.
    pub fn with_configuration(
        config: &Configuration,
        subject: &str,
        service: &str,
        private_claims: T,
        refresh_token_payload: Option<&JsonValue>,
    ) -> Result<Self, ::Error> {
        Self::with_configuration_and_time(
            config,
            subject,
            service,
            private_claims,
            refresh_token_payload,
            Utc::now(),
        )
    }

    /// Consumes self and encode the embedded JWT with signature.
    /// If the JWT is already encoded, this returns an error
    pub fn encode(mut self, secret: &jws::Secret) -> Result<Self, Error> {
        match self.token {
            jwt::jws::Compact::Encoded(_) => Err(Error::TokenAlreadyEncoded),
            jwt @ jwt::jws::Compact::Decoded { .. } => {
                self.token = jwt.into_encoded(secret)?;
                Ok(self)
            }
        }
    }

    /// Consumes self and decode the embedded JWT with signature verification
    /// If the JWT is already decoded, this returns an error
    pub fn decode(mut self, secret: &jws::Secret, algorithm: jwa::SignatureAlgorithm) -> Result<Self, Error> {
        match self.token {
            jwt @ jwt::jws::Compact::Encoded(_) => {
                self.token = jwt.into_decoded(secret, algorithm)?;
                Ok(self)
            }
            jwt::jws::Compact::Decoded { .. } => Err(Error::TokenAlreadyDecoded),
        }
    }

    fn serialize(self) -> Result<String, Error> {
        if self.is_decoded() {
            Err(Error::TokenNotEncoded)?
        }
        let serialized = serde_json::to_string(&self)?;
        Ok(serialized)
    }

    fn respond<'r>(self) -> Result<Response<'r>, Error> {
        let serialized = self.serialize()?;
        Response::build()
            .header(ContentType::JSON)
            .sized_body(Cursor::new(serialized))
            .ok()
    }

    /// Returns whether the wrapped token is decoded and verified
    pub fn is_decoded(&self) -> bool {
        match self.token {
            jwt::jws::Compact::Encoded(_) => false,
            jwt::jws::Compact::Decoded { .. } => true,
        }
    }

    /// Returns whether the wrapped token is encoded and signed
    pub fn is_encoded(&self) -> bool {
        !self.is_decoded()
    }

    /// Convenience function to extract the registered claims from a decoded token
    pub fn registered_claims(&self) -> Result<&jwt::RegisteredClaims, ::Error> {
        match self.token {
            jwt::jws::Compact::Encoded(_) => Err(Error::TokenNotDecoded)?,
            ref jwt @ jwt::jws::Compact::Decoded { .. } => {
                Ok(match_extract!(*jwt,
                                 jwt::jws::Compact::Decoded {
                                     payload: jwt::ClaimsSet { ref registered, .. },
                                     ..
                                 },
                                 registered)?)
            }
        }
    }

    /// Conveneince function to extract the private claims from a decoded token
    pub fn private_claims(&self) -> Result<&T, ::Error> {
        match self.token {
            jwt::jws::Compact::Encoded(_) => Err(Error::TokenNotDecoded)?,
            ref jwt @ jwt::jws::Compact::Decoded { .. } => {
                Ok(match_extract!(*jwt,
                                 jwt::jws::Compact::Decoded {
                                     payload: jwt::ClaimsSet { ref private, .. },
                                     ..
                                 },
                                 private)?)
            }
        }
    }

    /// Convenience function to extract the headers from a decoded token
    pub fn header(&self) -> Result<&jwt::jws::Header<jwt::Empty>, ::Error> {
        match self.token {
            jwt::jws::Compact::Encoded(_) => Err(Error::TokenNotDecoded)?,
            ref jwt @ jwt::jws::Compact::Decoded { .. } => {
                Ok(match_extract!(*jwt,
                                 jwt::jws::Compact::Decoded {
                                     ref header,
                                     ..
                                 },
                                 header)?)
            }
        }
    }

    /// Convenience method to extract the encoded token
    pub fn encoded_token(&self) -> Result<String, ::Error> {
        Ok(self.token.encoded().map_err(Error::JWTError)?.to_string())
    }

    /// Convenience method to obtain a reference to the refresh token
    pub fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }

    /// Consumes self, and encrypt and sign the embedded refresh token
    pub fn encrypt_refresh_token(mut self, secret: &jws::Secret, key: &jwk::JWK<jwt::Empty>) -> Result<Self, Error> {
        let refresh_token = self.refresh_token.ok_or_else(|| Error::NoRefreshToken)?;
        let refresh_token = refresh_token.encrypt(secret, key)?;
        self.refresh_token = Some(refresh_token);
        Ok(self)
    }

    /// Consumes self, and decrypt and verify the signature of the embedded refresh token
    pub fn decrypt_refresh_token(
        mut self,
        secret: &jws::Secret,
        key: &jwk::JWK<jwt::Empty>,
        signing_algorithm: jwa::SignatureAlgorithm,
        cek_algorithm: jwa::KeyManagementAlgorithm,
        enc_algorithm: jwa::ContentEncryptionAlgorithm,
    ) -> Result<Self, Error> {
        let refresh_token = self.refresh_token.ok_or_else(|| Error::NoRefreshToken)?;
        let refresh_token = refresh_token.decrypt(
            secret,
            key,
            signing_algorithm,
            cek_algorithm,
            enc_algorithm,
        )?;
        self.refresh_token = Some(refresh_token);
        Ok(self)
    }

    /// Returns whether there is a refresh token
    pub fn has_refresh_token(&self) -> bool {
        self.refresh_token.is_some()
    }
}

impl<'r, T: Serialize + DeserializeOwned + 'static> Responder<'r> for Token<T> {
    fn respond_to(self, request: &Request) -> Result<Response<'r>, Status> {
        match self.respond() {
            Ok(r) => Ok(r),
            Err(e) => Err::<String, Error>(e).respond_to(request),
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
    ByteSequence(ByteSequence),
    /// Path to a file containing the byte sequence for HMAC signing or encryption key
    Bytes {
        /// Path to the file containing the byte sequence for a HMAC signing or encryption key
        path: String,
    },
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
    pub(super) fn for_signing(&self) -> Result<jws::Secret, Error> {
        match *self {
            Secret::None => Ok(jws::Secret::None),
            Secret::ByteSequence(ref bytes) => Ok(jws::Secret::Bytes(bytes.as_bytes())),
            Secret::Bytes { ref path } => Ok(jws::Secret::Bytes(Self::read_file_to_bytes(path)?)),
            Secret::RSAKeyPair { ref rsa_private, .. } => Ok(jws::Secret::rsa_keypair_from_file(rsa_private)?),
        }
    }

    /// Create a [`jws::Secret`] for the purpose of verifying signatures
    pub(super) fn for_verification(&self) -> Result<jws::Secret, Error> {
        match *self {
            Secret::None => Ok(jws::Secret::None),
            Secret::ByteSequence(ref bytes) => Ok(jws::Secret::Bytes(bytes.as_bytes())),
            Secret::Bytes { ref path } => Ok(jws::Secret::Bytes(Self::read_file_to_bytes(path)?)),
            Secret::RSAKeyPair { ref rsa_public, .. } => Ok(jws::Secret::public_key_from_file(rsa_public)?),
        }
    }

    /// Create a JWK for the purpose of encryption
    pub(super) fn for_encryption(&self) -> Result<jwk::JWK<jwt::Empty>, Error> {
        match *self {
            Secret::None => Err(Error::GenericError(
                "A key is required for encryption".to_string(),
            )),
            Secret::ByteSequence(ref bytes) => Ok(jwk::JWK::new_octect_key(
                &bytes.as_bytes(),
                Default::default(),
            )),
            Secret::Bytes { ref path } => {
                Ok(jwk::JWK::new_octect_key(
                    &Self::read_file_to_bytes(path)?,
                    Default::default(),
                ))
            }
            Secret::RSAKeyPair { .. } => Err(Error::GenericError("Not supported yet".to_string())),
        }
    }

    /// Create a JWK for the purpose of decryption
    pub(super) fn for_decryption(&self) -> Result<jwk::JWK<jwt::Empty>, Error> {
        // For now
        self.for_encryption()
    }

    fn read_file_to_bytes(path: &str) -> Result<Vec<u8>, Error> {
        let mut file = File::open(path)?;
        let mut bytes = Vec::<u8>::new();
        let _ = file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

/// Keys prepared in a form directly usable for cryptographic operations. This prevents us from having to
/// repeatedly read keys from the file system. Users should prepare the keys from `Configuration` using
/// `Configuration::keys()` and then use this struct to retrieve keys from instead of the functions from `Secret`.
pub struct Keys {
    /// Key used to signed tokens
    pub signing: jws::Secret,
    /// Key used to verify token signatures
    pub signature_verification: jws::Secret,
    /// Key used to encrypt tokens. Used if Refresh tokens are enabled.
    pub encryption: Option<jwk::JWK<jwt::Empty>>,
    /// Key used to decrypt tokens. Used if Refresh tokens are enabled.
    pub decryption: Option<jwk::JWK<jwt::Empty>>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use chrono::{DateTime, NaiveDateTime, Utc};
    use serde_json;

    use {JsonValue, JsonMap};
    use jwt;
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

    fn make_config(refresh_token: bool) -> Configuration {
        let refresh_token = if refresh_token {
            Some(RefreshTokenConfiguration {
                cek_algorithm: jwt::jwa::KeyManagementAlgorithm::A256GCMKW,
                enc_algorithm: jwt::jwa::ContentEncryptionAlgorithm::A256GCM,
                key: Secret::ByteSequence(ByteSequence::Bytes(vec![0; 256/8])),
                expiry_duration: Duration::from_secs(86400),
            })
        } else {
            None
        };

        let allowed_origins = ["https://www.example.com"];
        let (allowed_origins, _) = ::cors::AllowedOrigins::some(&allowed_origins);

        Configuration {
            issuer: FromStr::from_str("https://www.acme.com").unwrap(),
            allowed_origins: allowed_origins,
            audience: jwt::SingleOrMultiple::Single(FromStr::from_str("https://www.example.com/").unwrap()),
            signature_algorithm: Some(jwt::jwa::SignatureAlgorithm::HS512),
            secret: Secret::ByteSequence(ByteSequence::String("secret".to_string())),
            expiry_duration: Duration::from_secs(120),
            refresh_token: refresh_token,
        }
    }

    fn refresh_token_payload() -> JsonValue {
        let mut map = JsonMap::with_capacity(1);
        let _ = map.insert("test".to_string(), From::from("foobar"));
        JsonValue::Object(map)
    }

    fn make_refresh_token() -> RefreshToken {
        RefreshToken::new_decrypted(
            "foobar",
            &FromStr::from_str("https://www.acme.com").unwrap(),
            &jwt::SingleOrMultiple::Single(FromStr::from_str("https://www.example.com").unwrap()),
            Duration::from_secs(120),
            &refresh_token_payload(),
            Some(Default::default()),
            jwt::jwa::KeyManagementAlgorithm::A256GCMKW,
            jwt::jwa::ContentEncryptionAlgorithm::A256GCM,
            Utc::now(),
        ).unwrap()
    }

    fn make_token(refresh_token: bool) -> Token<TestClaims> {
        let refresh_token = if refresh_token {
            Some(make_refresh_token())
        } else {
            None
        };

        Token {
            token: jwt::JWT::new_decoded(
                jwt::jws::Header::default(),
                jwt::ClaimsSet {
                    private: Default::default(),
                    registered: Default::default(),
                },
            ),
            expires_in: Duration::from_secs(120),
            issued_at: Utc::now(),
            refresh_token: refresh_token,
        }
    }

    #[test]
    fn refresh_token_encryption_round_trip() {
        let key = jwt::jwk::JWK::new_octect_key(&[0; 256 / 8], Default::default());
        let signing_secret = jwt::jws::Secret::bytes_from_str("secret");

        let refresh_token = make_refresh_token();
        assert!(refresh_token.decrypted());

        let encrypted_refresh_token = not_err!(refresh_token.clone().encrypt(&signing_secret, &key));
        assert!(encrypted_refresh_token.encrypted());

        let decrypted_refresh_token = not_err!(encrypted_refresh_token.decrypt(&signing_secret, &key,
                                                                               Default::default(),
                                                         jwt::jwa::KeyManagementAlgorithm::A256GCMKW,
                                                         jwt::jwa::ContentEncryptionAlgorithm::A256GCM));
        assert!(decrypted_refresh_token.decrypted());

        let actual_refresh_token_payload: &JsonValue = decrypted_refresh_token.payload().unwrap();
        let map = actual_refresh_token_payload.as_object().unwrap();
        assert_eq!(map.get("test").unwrap().as_str().unwrap(), "foobar");
    }

    #[test]
    fn serializing_and_deserializing_round_trip() {
        let key = jwt::jwk::JWK::new_octect_key(&[0; 256 / 8], Default::default());
        let signing_secret = jwt::jws::Secret::bytes_from_str("secret");
        let token = make_token(true);

        let token = not_err!(token.encode(&signing_secret));
        assert!(token.is_encoded());
        let token = not_err!(token.encrypt_refresh_token(&signing_secret, &key));
        assert!(token.refresh_token().unwrap().encrypted());

        let serialized = not_err!(serde_json::to_string_pretty(&token));
        let deserialized: Token<TestClaims> = not_err!(serde_json::from_str(&serialized));
        assert_eq!(deserialized, token);

        let token = not_err!(token.decode(&signing_secret, Default::default()));
        let token = not_err!(token.decrypt_refresh_token(&signing_secret, &key, Default::default(),
                                                         jwt::jwa::KeyManagementAlgorithm::A256GCMKW,
                                                         jwt::jwa::ContentEncryptionAlgorithm::A256GCM));

        let private = not_err!(token.private_claims());
        assert_eq!(*private, Default::default());

        let refresh_token = token.refresh_token().unwrap();
        let actual_refresh_token_payload: &JsonValue = refresh_token.payload().unwrap();
        let map = actual_refresh_token_payload.as_object().unwrap();
        assert_eq!(map.get("test").unwrap().as_str().unwrap(), "foobar");
    }

    #[test]
    #[should_panic(expected = "TokenAlreadyEncoded")]
    fn panics_when_encoding_encoded() {
        let token = make_token(false);
        let token = not_err!(token.encode(&jwt::jws::Secret::bytes_from_str("secret")));
        let _ = token
            .encode(&jwt::jws::Secret::bytes_from_str("secret"))
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "TokenAlreadyDecoded")]
    fn panics_when_decoding_decoded() {
        let token = make_token(false);
        let _ = token
            .decode(
                &jwt::jws::Secret::bytes_from_str("secret"),
                Default::default(),
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "RefreshTokenAlreadyEncrypted")]
    fn panics_when_encrypting_encrypted() {
        let key = jwt::jwk::JWK::new_octect_key(&[0; 256 / 8], Default::default());
        let signing_secret = jwt::jws::Secret::bytes_from_str("secret");

        let token = make_token(true);
        let token = not_err!(token.encrypt_refresh_token(&signing_secret, &key));
        let _ = token.encrypt_refresh_token(&signing_secret, &key).unwrap();
    }

    #[test]
    #[should_panic(expected = "RefreshTokenAlreadyDecrypted")]
    fn panics_when_decrypting_decrypted() {
        let key = jwt::jwk::JWK::new_octect_key(&[0; 256 / 8], Default::default());
        let signing_secret = jwt::jws::Secret::bytes_from_str("secret");

        let token = make_token(true);
        let _ = token
            .decrypt_refresh_token(
                &signing_secret,
                &key,
                Default::default(),
                jwt::jwa::KeyManagementAlgorithm::A256GCMKW,
                jwt::jwa::ContentEncryptionAlgorithm::A256GCM,
            )
            .unwrap();
    }

    #[test]
    fn token_serialization_smoke_test() {
        let expected_token = make_token(false);
        let token = not_err!(expected_token.clone().encode(&jwt::jws::Secret::bytes_from_str("secret")));
        let serialized = not_err!(token.serialize());

        let deserialized: Token<TestClaims> = not_err!(serde_json::from_str(&serialized));
        let actual_token = not_err!(deserialized.decode(&jwt::jws::Secret::bytes_from_str("secret"),
                                                        Default::default()));
        assert_eq!(expected_token, actual_token);
    }

    #[test]
    fn token_response_smoke_test() {
        let expected_token = make_token(false);
        let token = not_err!(expected_token.clone().encode(&jwt::jws::Secret::bytes_from_str("secret")));
        let mut response = not_err!(token.respond());

        assert_eq!(response.status(), Status::Ok);
        let body_str = not_none!(response.body().and_then(|body| body.into_string()));
        let deserialized: Token<TestClaims> = not_err!(serde_json::from_str(&body_str));
        let actual_token = not_err!(deserialized.decode(&jwt::jws::Secret::bytes_from_str("secret"),
                                                        Default::default()));
        assert_eq!(expected_token, actual_token);
    }

    #[test]
    fn secrets_are_transformed_for_signing_correctly() {
        let none = Secret::None;
        assert_matches_non_debug!(not_err!(none.for_signing()), jwt::jws::Secret::None);

        let string = Secret::ByteSequence(ByteSequence::String("secret".to_string()));
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

        let string = Secret::ByteSequence(ByteSequence::String("secret".to_string()));
        assert_matches_non_debug!(not_err!(string.for_verification()), jwt::jws::Secret::Bytes(_));

        let rsa = Secret::RSAKeyPair {
            rsa_private: "test/fixtures/rsa_private_key.der".to_string(),
            rsa_public: "test/fixtures/rsa_public_key.der".to_string(),
        };
        assert_matches_non_debug!(not_err!(rsa.for_verification()), jwt::jws::Secret::PublicKey(_));
    }

    #[test]
    fn token_created_with_refresh_token_disabled() {
        let configuration = make_config(false);

        let mut map = JsonMap::with_capacity(1);
        let _ = map.insert("test".to_string(), From::from("foobar"));
        let refresh_token_payload = JsonValue::Object(map);

        let now = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
        let expected_expiry = now + chrono::Duration::from_std(Duration::from_secs(120)).unwrap();
        let token = not_err!(Token::<TestClaims>::with_configuration_and_time(&configuration,
                                                                              "Donald Trump",
                                                                              "https://www.example.com/",
                                                                              Default::default(),
                                                                              Some(&refresh_token_payload),
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
        assert_eq!(header.registered.algorithm, jwt::jwa::SignatureAlgorithm::HS512);

        // Assert refresh token
        assert!(token.refresh_token().is_none());
    }

    #[test]
    fn token_created_with_no_refresh_token_payload() {
        let configuration = make_config(true);

        let now = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
        let expected_expiry = now + chrono::Duration::from_std(Duration::from_secs(120)).unwrap();
        let token = not_err!(Token::<TestClaims>::with_configuration_and_time(&configuration,
                                                                              "Donald Trump",
                                                                              "https://www.example.com/",
                                                                              Default::default(),
                                                                              None,
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
        assert_eq!(header.registered.algorithm, jwt::jwa::SignatureAlgorithm::HS512);

        // Assert refresh token
        assert!(token.refresh_token().is_none());
    }

    #[test]
    fn token_created_with_refresh_token() {
        let configuration = make_config(true);

        let mut map = JsonMap::with_capacity(1);
        let _ = map.insert("test".to_string(), From::from("foobar"));
        let refresh_token_payload = JsonValue::Object(map);

        let now = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
        let expected_expiry = now + chrono::Duration::from_std(Duration::from_secs(120)).unwrap();
        let token = not_err!(Token::<TestClaims>::with_configuration_and_time(&configuration,
                                                                              "Donald Trump",
                                                                              "https://www.example.com/",
                                                                              Default::default(),
                                                                              Some(&refresh_token_payload),
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
        assert_eq!(header.registered.algorithm, jwt::jwa::SignatureAlgorithm::HS512);

        // Assert refresh token
        let refresh_token = token.refresh_token().unwrap();
        let actual_refresh_token_payload: &JsonValue = refresh_token.payload().unwrap();
        assert_eq!(*actual_refresh_token_payload, refresh_token_payload);
    }

    #[test]
    #[should_panic(expected = "InvalidService")]
    fn validates_service_correctly() {
        let configuration = make_config(true);

        let now = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
        let _ = Token::<TestClaims>::with_configuration_and_time(
            &configuration,
            "Donald Trump",
            "invalid",
            Default::default(),
            None,
            now,
        ).unwrap();
    }

    #[test]
    fn refresh_token_validates_correctly() {
        let configuration = make_config(true);
        let refresh_token = make_refresh_token();
        not_err!(refresh_token.validate("https://www.example.com/", &configuration, None));
    }

    /// Token does not have an issuer field
    #[test]
    #[should_panic(expected = "InvalidIssuer")]
    fn refresh_token_validates_missing_issuer() {
        let configuration = make_config(true);

        let refresh_token = make_refresh_token();
        let mut jwe = refresh_token.unwrap();
        {
            let jws = jwe.payload_mut().unwrap();
            let claims_set = jws.payload_mut().unwrap();
            claims_set.registered.issuer = None;
        }
        let refresh_token = RefreshToken(jwe);

        refresh_token
            .validate("https://www.example.com/", &configuration, None)
            .unwrap();
    }

    /// Token does not have an audience field
    #[test]
    #[should_panic(expected = "InvalidAudience")]
    fn refresh_token_validates_missing_audience() {
        let configuration = make_config(true);

        let refresh_token = make_refresh_token();
        let mut jwe = refresh_token.unwrap();
        {
            let jws = jwe.payload_mut().unwrap();
            let claims_set = jws.payload_mut().unwrap();
            claims_set.registered.audience = None;
        }
        let refresh_token = RefreshToken(jwe);

        refresh_token
            .validate("https://www.example.com/", &configuration, None)
            .unwrap();
    }

    /// An invalid service was requested for
    #[test]
    #[should_panic(expected = "InvalidService")]
    fn refresh_token_validates_invalid_service() {
        let configuration = make_config(true);
        let refresh_token = make_refresh_token();
        refresh_token
            .validate("https://www.invalid.com/", &configuration, None)
            .unwrap();
    }

    /// Configuration has the right audience request configured, but the token does not indicate that it is for the
    /// audience requested
    #[test]
    #[should_panic(expected = "InvalidAudience")]
    fn refresh_token_validates_mismatch_service_and_audience() {
        let mut configuration = make_config(true);
        configuration.audience = jwt::SingleOrMultiple::Single(FromStr::from_str("https://www.invalid.com/").unwrap());
        let refresh_token = make_refresh_token();
        refresh_token
            .validate("https://www.invalid.com/", &configuration, None)
            .unwrap();
    }

    /// Token's audience is not a subset of the connfigured audience
    #[test]
    #[should_panic(expected = "InvalidAudience")]
    fn refresh_token_validates_invalid_audience() {
        let configuration = make_config(true);

        let refresh_token = make_refresh_token();
        let mut jwe = refresh_token.unwrap();
        {
            let jws = jwe.payload_mut().unwrap();
            let claims_set = jws.payload_mut().unwrap();
            claims_set.registered.audience = Some(jwt::SingleOrMultiple::Multiple(
                vec![FromStr::from_str("https://www.invalid.com/").unwrap(),
                                                          FromStr::from_str("https://www.example.com/").unwrap(),
                                                         ],
            ));
        }
        let refresh_token = RefreshToken(jwe);

        refresh_token
            .validate("https://www.example.com/", &configuration, None)
            .unwrap();
    }

    /// Token's issuer is not expected
    #[test]
    #[should_panic(expected = "InvalidIssuer")]
    fn refresh_token_validates_invalid_issuer() {
        let configuration = make_config(true);

        let refresh_token = make_refresh_token();
        let mut jwe = refresh_token.unwrap();
        {
            let jws = jwe.payload_mut().unwrap();
            let claims_set = jws.payload_mut().unwrap();
            claims_set.registered.issuer = Some(FromStr::from_str("https://www.invalid.com/").unwrap());
        }
        let refresh_token = RefreshToken(jwe);

        refresh_token
            .validate("https://www.example.com/", &configuration, None)
            .unwrap();
    }

    /// Issued at time is required
    #[test]
    #[should_panic(expected = "MissingRequired(\"iat\")")]
    fn refresh_token_validates_missing_issued_at() {
        let configuration = make_config(true);

        let refresh_token = make_refresh_token();
        let mut jwe = refresh_token.unwrap();
        {
            let jws = jwe.payload_mut().unwrap();
            let claims_set = jws.payload_mut().unwrap();
            claims_set.registered.issued_at = None;
        }
        let refresh_token = RefreshToken(jwe);

        refresh_token
            .validate("https://www.example.com/", &configuration, None)
            .unwrap();
    }

    /// Not before time is required
    #[test]
    #[should_panic(expected = "MissingRequired(\"nbf\")")]
    fn refresh_token_validates_missing_not_before() {
        let configuration = make_config(true);

        let refresh_token = make_refresh_token();
        let mut jwe = refresh_token.unwrap();
        {
            let jws = jwe.payload_mut().unwrap();
            let claims_set = jws.payload_mut().unwrap();
            claims_set.registered.not_before = None;
        }
        let refresh_token = RefreshToken(jwe);

        refresh_token
            .validate("https://www.example.com/", &configuration, None)
            .unwrap();
    }

    /// Expiry time is required
    #[test]
    #[should_panic(expected = "MissingRequired(\"exp\")")]
    fn refresh_token_validates_missing_expiry() {
        let configuration = make_config(true);

        let refresh_token = make_refresh_token();
        let mut jwe = refresh_token.unwrap();
        {
            let jws = jwe.payload_mut().unwrap();
            let claims_set = jws.payload_mut().unwrap();
            claims_set.registered.expiry = None;
        }
        let refresh_token = RefreshToken(jwe);

        refresh_token
            .validate("https://www.example.com/", &configuration, None)
            .unwrap();
    }
}
