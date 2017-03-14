use std::ops::Deref;
use std::error;
use std::fmt;
use std::io::Cursor;
use std::time::Duration;

use chrono::{DateTime, UTC};
use jwt::{self, jws};
use hyper;
use rocket;
use rocket::http::{ContentType, Status};
use rocket::http::Method::*;
use rocket::response::{Response, Responder};
use rocket::State;
use serde::{Serialize, Deserialize};
use serde_json;

use cors;
use header;

#[derive(Debug)]
pub enum Error {
    /// Raised when attempting to encode an already encoded token
    TokenAlreadyEncoded,
    /// Raised when attempting to decode an already decoded token
    TokenAlreadyDecoded,
    /// Raised when attempting to use a decoded token in a response
    TokenNotEncoded,

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
            Error::TokenNotEncoded => "Token is not encoded and cannot be used in a response",
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
        Err(Status::InternalServerError)
    }
}

#[derive(Default, Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct PrivateClaim {}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Token<T: Serialize + Deserialize> {
    pub token: jwt::JWT<T>,
    #[serde(with = "::serde_custom::duration")]
    pub expires_in: Duration,
    pub issued_at: DateTime<UTC>,
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
    pub fn new(header: jws::Header, claims_set: jwt::ClaimsSet<T>, expires_in: &Duration) -> Self {
        Token {
            token: jwt::JWT::new_decoded(header, claims_set),
            expires_in: *expires_in,
            issued_at: UTC::now(),
            refresh_token: None,
        }
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

pub struct TokenGetterCorsOptions(cors::Options);
impl_deref!(TokenGetterCorsOptions, cors::Options);

const TOKEN_GETTER_METHODS: &[rocket::http::Method] = &[Get];
const TOKEN_GETTER_HEADERS: &'static [&'static str] = &["Authorization"];

impl TokenGetterCorsOptions {
    pub fn new(config: &::Configuration) -> Self {
        TokenGetterCorsOptions(cors::Options {
                                   allowed_origins: config.allowed_origins.clone(),
                                   allowed_methods: TOKEN_GETTER_METHODS.iter().cloned().collect(),
                                   allowed_headers: TOKEN_GETTER_HEADERS.iter().map(|s| s.to_string().into()).collect(),
                                   allow_credentials: true,
                                   ..Default::default()
                               })
    }
}

#[derive(FromForm, Default, Clone, Debug)]
struct AuthParam {
    service: String,
    scope: String,
    offline_token: Option<bool>,
}

#[allow(unmounted_route)]
// mounted via `::launch()`
#[options("/?<_auth_param>")]
#[allow(needless_pass_by_value)]
fn token_getter_options(origin: cors::Origin,
                        method: cors::AccessControlRequestMethod,
                        headers: cors::AccessControlRequestHeaders,
                        options: State<TokenGetterCorsOptions>,
                        _auth_param: AuthParam)
                        -> Result<cors::Response<()>, cors::Error> {
    options.preflight(&origin, &method, Some(&headers))
}

#[allow(unmounted_route)]
// mounted via `::launch()`
#[get("/?<_auth_param>")]
#[allow(needless_pass_by_value)]
fn token_getter(origin: cors::Origin,
                authentication: header::Authorization<hyper::header::Basic>,
                _auth_param: AuthParam,
                configuration: State<::Configuration>,
                cors_options: State<TokenGetterCorsOptions>)
                -> Result<cors::Response<Token<PrivateClaim>>, ::Error> {

    let ::header::Authorization(hyper::header::Authorization(hyper::header::Basic { username, .. })) = authentication;
    let token = configuration.make_token::<PrivateClaim>(&username, Default::default())?;
    let token = token.encode(configuration.secret.for_signing()?)?;
    Ok(cors_options.respond(token, &origin)?)
}

#[cfg(test)]
mod tests {
    use std::default::Default;
    use std::time::Duration;
    use std::str::FromStr;

    use hyper;
    use jwt;
    use rocket::http::Header;
    use rocket::http::Method::*;
    use rocket::testing::MockRequest;
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
        assert_matches!(token, Token { token: jwt::JWT::Encoded(_), .. });

        let token = not_err!(token.decode(jwt::jws::Secret::bytes_from_str("secret"), Default::default()));
        let private = assert_matches!(token,
                                      Token {
                                          token: jwt::JWT::Decoded { claims_set: jwt::ClaimsSet {private, .. },
                                                                     .. },
                                          .. },
                                      private);

        assert_eq!(private, Default::default());
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
    fn token_getter_options_test() {
        // Ignite rocket
        let allowed_origins = ["https://www.example.com"];
        let (allowed_origins, _) = ::cors::AllowedOrigins::new_from_str_list(&allowed_origins);
        let configuration = ::Configuration {
            issuer: "https://www.acme.com".to_string(),
            allowed_origins: allowed_origins,
            audience: Some(jwt::SingleOrMultipleStrings::Single("https://www.example.com".to_string())),
            signature_algorithm: Some(jwt::jws::Algorithm::HS512),
            secret: Secret::String("secret".to_string()),
            expiry_duration: Duration::from_secs(120),
        };
        let token_getter_cors_options = TokenGetterCorsOptions::new(&configuration);

        let rocket = rocket::ignite()
            .mount("/",
                   routes![::token::token_getter_options, ::token::token_getter])
            .manage(configuration)
            .manage(token_getter_cors_options);

        // Make headers
        let origin_header = Header::from(not_err!(hyper::header::Origin::from_str("https://www.example.com")));
        let method_header = Header::from(hyper::header::AccessControlRequestMethod(hyper::method::Method::Get));
        let request_headers = hyper::header::AccessControlRequestHeaders(vec![FromStr::from_str("Authorization")
                                                                                  .unwrap()]);
        let request_headers = Header::from(request_headers);

        // Make and dispatch request
        let mut req = MockRequest::new(Options, "/?service=foobar&scope=all")
            .header(origin_header)
            .header(method_header)
            .header(request_headers);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    #[allow(deprecated)]
    fn token_getter_get_test() {
        // Ignite rocket
        let allowed_origins = ["https://www.example.com"];
        let (allowed_origins, _) = ::cors::AllowedOrigins::new_from_str_list(&allowed_origins);
        let configuration = ::Configuration {
            issuer: "https://www.acme.com".to_string(),
            allowed_origins: allowed_origins,
            audience: Some(jwt::SingleOrMultipleStrings::Single("https://www.example.com".to_string())),
            signature_algorithm: Some(jwt::jws::Algorithm::HS512),
            secret: Secret::String("secret".to_string()),
            expiry_duration: Duration::from_secs(120),
        };
        let token_getter_cors_options = TokenGetterCorsOptions::new(&configuration);

        let rocket = rocket::ignite()
            .mount("/",
                   routes![::token::token_getter_options, ::token::token_getter])
            .manage(configuration)
            .manage(token_getter_cors_options);

        // Make headers
        let origin_header = Header::from(not_err!(hyper::header::Origin::from_str("https://www.example.com")));
        let auth_header = hyper::header::Authorization(hyper::header::Basic {
                                                           username: "Aladdin".to_owned(),
                                                           password: Some("open sesame".to_string()),
                                                       });
        let auth_header = Header::new("Authorization",
                                      format!("{}", hyper::header::HeaderFormatter(&auth_header)));
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/?service=foobar&scope=all").header(origin_header).header(auth_header);
        let mut response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
        let body_str = not_none!(response.body().and_then(|body| body.into_string()));

        let deserialized: Token<PrivateClaim> = not_err!(serde_json::from_str(&body_str));
        let actual_token =
            not_err!(deserialized.decode(jwt::jws::Secret::bytes_from_str("secret"), jwt::jws::Algorithm::HS512));

        let registered = assert_matches!(actual_token,
                                         Token {
                                             token: jwt::JWT::Decoded {
                                                 claims_set: jwt::ClaimsSet { registered, .. },
                                                 ..
                                             },
                                             ..
                                         },
                                         registered);

        assert_eq!(Some("https://www.acme.com".to_string()), registered.issuer);
        assert_eq!(Some(jwt::SingleOrMultipleStrings::Single("https://www.example.com".to_string())), registered.audience);
    }
}
