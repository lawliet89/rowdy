//! Authentication module, including traits for identity provider and `Responder`s for
//! authentication.
use std::error;
use std::fmt;
use std::ops::Deref;

use hyper;
use hyper::header;
use rocket;
use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};
use rocket::response;
use rocket::Outcome;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub mod util;

mod noop;
pub use self::noop::NoOp;
pub use self::noop::NoOpConfiguration;

#[cfg(feature = "simple_authenticator")]
pub mod simple;
#[cfg(feature = "simple_authenticator")]
pub use self::simple::SimpleAuthenticator;
#[cfg(feature = "simple_authenticator")]
pub use self::simple::SimpleAuthenticatorConfiguration;

#[cfg(feature = "ldap_authenticator")]
mod ldap;
#[cfg(feature = "ldap_authenticator")]
pub use self::ldap::LdapAuthenticator;

use crate::JsonValue;

/// Re-exported [`hyper::header::Scheme`]
pub type Scheme = dyn hyper::header::Scheme<Err = hyper::error::Error>;
/// Re-exported [`hyper::header::Basic`].
pub type Basic = hyper::header::Basic;
/// Re-exported [`hyper::header::Bearer`].
pub type Bearer = hyper::header::Bearer;

/// A typedef for an `Authenticator` trait object that requires HTTP Basic authentication
pub type BasicAuthenticator = dyn Authenticator<Basic>;
/// A typedef for an `Authenticator` trait object that requires Bearer authentication.
pub type BearerAuthenticator = dyn Authenticator<Bearer>;
/// A typedef for an `Authenticator` trait object that uses an arbitrary string
pub type StringAuthenticator = dyn Authenticator<String>;

/// Authentication errors
#[derive(Debug)]
pub enum Error {
    /// Authentication was attempted successfully, but failed because of bad user credentials,
    /// or other reasons.
    AuthenticationFailure,
    /// A generic error
    GenericError(String),
    /// An error due to `hyper`, such as header parsing failure
    HyperError(hyper::error::Error),
    /// The `Authorization` HTTP request header was required but was missing. This variant will
    /// `respond` with the
    /// appropriate `WWW-Authenticate` header.
    MissingAuthorization {
        /// The HTTP basic authentication realm
        realm: String,
    },
}

impl_from_error!(String, Error::GenericError);
impl_from_error!(hyper::error::Error, Error::HyperError);

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::AuthenticationFailure => "Authentication has failed",
            Error::MissingAuthorization { .. } => {
                "The request header `Authorization` is required but is missing"
            }
            Error::GenericError(ref e) => &**e,
            Error::HyperError(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::HyperError(ref e) => Some(e),
            _ => Some(self),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::HyperError(ref e) => fmt::Display::fmt(e, f),
            _ => write!(f, "{}", error::Error::description(self)),
        }
    }
}

impl<'r> response::Responder<'r> for Error {
    fn respond_to(self, _: &Request<'_>) -> Result<response::Response<'r>, Status> {
        error_!("Authentication Error: {:?}", self);
        match self {
            Error::MissingAuthorization { ref realm } => {
                // TODO: Support other schemes!
                let www_header =
                    rocket::http::Header::new("WWW-Authenticate", format!("Basic realm={}", realm));

                Ok(response::Response::build()
                    .status(Status::Unauthorized)
                    .header(www_header)
                    .finalize())
            }
            Error::AuthenticationFailure => Err(Status::Unauthorized),
            Error::HyperError(_) => Err(Status::BadRequest),
            _ => Err(Status::InternalServerError),
        }
    }
}

/// `Authorization` HTTP Request Header
#[derive(Debug)]
pub struct Authorization<S: header::Scheme + 'static>(pub header::Authorization<S>);

impl<'a, 'r, S: header::Scheme + 'static> FromRequest<'a, 'r> for Authorization<S> {
    type Error = Error;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Error> {
        match request.headers().get_one("Authorization") {
            Some(authorization) => match Self::new(authorization) {
                Err(_) => Outcome::Forward(()),
                Ok(parsed) => Outcome::Success(parsed),
            },
            None => Outcome::Forward(()),
        }
    }
}

impl<S: header::Scheme + 'static> Authorization<S> {
    /// Create a new Authorization header
    pub fn new<'a>(header: &'a str) -> Result<Self, Error> {
        use hyper::header::Header;

        let bytes: Vec<u8> = header.as_bytes().to_vec();
        let parsed = header::Authorization::parse_header(&[bytes])?;
        Ok(Authorization(parsed))
    }

    /// Convenience function to check if the Authorization is `Basic`
    pub fn is_basic(&self) -> bool {
        if let Some("Basic") = S::scheme() {
            true
        } else {
            false
        }
    }

    /// Convenience function to check if the Authorization is `Bearer`
    pub fn is_bearer(&self) -> bool {
        if let Some("Bearer") = S::scheme() {
            true
        } else {
            false
        }
    }

    /// Convenience function to check if the Authorization is `None`
    pub fn is_string(&self) -> bool {
        S::scheme().is_none()
    }
}

impl Authorization<Basic> {
    /// Convenience method to retrieve the username from a HTTP Basic Authorization request header
    pub fn username(&self) -> String {
        let Authorization(header::Authorization(Basic { ref username, .. })) = *self;
        username.to_string()
    }

    /// Convenience method to retrieve the password from a HTTP Basic Authorization request header
    pub fn password(&self) -> Option<String> {
        let Authorization(header::Authorization(Basic { ref password, .. })) = *self;
        password.clone()
    }
}

impl Authorization<Bearer> {
    /// Convenience method to retrieve the token from a bearer Authorization request header.
    pub fn token(&self) -> String {
        let Authorization(header::Authorization(Bearer { ref token })) = *self;
        token.to_string()
    }
}

impl Authorization<String> {
    /// Convenience method to retrieve the token from an arbitrary Authorization request header.
    pub fn string(&self) -> String {
        let Authorization(header::Authorization(ref s)) = *self;
        s.to_string()
    }
}

impl<S: header::Scheme + 'static> Deref for Authorization<S> {
    type Target = header::Authorization<S>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Authenticator trait to be implemented by identity provider (idp) adapters to
/// provide authentication.
/// Each idp may support all the
/// [schemes](https://hyper.rs/hyper/v0.10.5/hyper/header/trait.Scheme.html)
/// supported, or just one.
///
/// Usually, you will want to include an `Authenticator` trait object as part of Rocket's
/// [managed state](https://rocket.rs/guide/state/). Before you can do that, however,
/// you will need to `Box` it up.
/// See example below.
///
/// # Examples
///
/// # No-op authenticator
/// You can refer to the [source code](../../src/rowdy/auth/noop.rs.html) for the `NoOp`
/// authenticator for a simple implementation.
///
/// ## Simple Authenticator
///
/// Refer to the `MockAuthenticator`[../../src/rowdy/auth/mod.rs.html] implemented
///  in the test code for this module.
pub trait Authenticator<S: header::Scheme + 'static>: Send + Sync {
    /// Verify the credentials provided in the headers with the authenticator for
    /// the initial issuing of Access Tokens.
    ///
    /// If the Authenticator supports re-issuing of access tokens subsequently using refresh tokens,
    /// and it is requested for, the function should return a `JsonValue`
    /// containing the payload to include with the refresh token.
    ///
    /// Users should not user`authenticate` directly and use `prepare_authentication_response`
    /// instead.
    fn authenticate(
        &self,
        authorization: &Authorization<S>,
        include_refresh_payload: bool,
    ) -> Result<AuthenticationResult, crate::Error>;

    /// Verify the credentials provided with the refresh token payload, if supported by the
    /// authenticator.
    ///
    /// A default implementation that returns an `Err(::Error::UnsupportedOperation)` is provided.
    ///
    /// Users should not user `authenticate` directly and use `prepare_refresh_response` instead.
    fn authenticate_refresh_token(
        &self,
        _payload: &JsonValue,
    ) -> Result<AuthenticationResult, crate::Error> {
        Err(crate::Error::UnsupportedOperation)
    }

    /// Prepare a response to an authentication request
    /// by first verifying credentials. If validation fails, will return an `Err` with the response
    /// to be sent. Otherwise, the unwrapped authentication result will be returned in an `Ok`.
    /// This function will also check that the authenticator behaves correctly by checking that
    /// it does not return a refresh token payload when it is not requested for
    fn prepare_authentication_response(
        &self,
        authorization: &Authorization<S>,
        request_refresh_token: bool,
    ) -> Result<AuthenticationResult, crate::Error> {
        let result = self.authenticate(authorization, request_refresh_token)?;
        if !request_refresh_token && result.refresh_payload.is_some() {
            Err(Error::GenericError(
                "Misbehaving authenticator: refresh token payload was \
                 returned when it was not requested for"
                    .to_string(),
            ))?;
        }
        Ok(result)
    }

    /// Prepare a response to a refresh request by first verifying the refresh payload.
    ///
    /// If validation fails, will return an `Err` with the response
    /// to be sent. Otherwise, the unwrapped authentication result will be returned in an `Ok`.
    /// This function will also check that the authenticator behaves correctly by checking that
    /// it does not return a refresh token payload
    fn prepare_refresh_response(
        &self,
        refresh_payload: &JsonValue,
    ) -> Result<AuthenticationResult, crate::Error> {
        let result = self.authenticate_refresh_token(refresh_payload)?;
        if result.refresh_payload.is_some() {
            Err(Error::GenericError(
                "Misbehaving authenticator: refresh token payload was \
                 returned for a refresh operation"
                    .to_string(),
            ))?;
        }
        Ok(result)
    }
}

/// Convenience function to respond with a missing authorization error
pub fn missing_authorization<T>(realm: &str) -> Result<T, crate::Error> {
    Err(Error::MissingAuthorization {
        realm: realm.to_string(),
    })?
}

/// Configuration for the associated type `Authenticator`. [`crate::Configuration`] expects its
/// `authenticator` field to implement this trait.
///
/// Before launching, `rowdy` will attempt to make an `Authenticator` based off the
/// configuration by calling the `make_authenticator` method.
pub trait AuthenticatorConfiguration<S: header::Scheme + 'static>:
    Send + Sync + Serialize + DeserializeOwned + 'static
{
    /// The `Authenticator` type this configuration is associated with
    type Authenticator: Authenticator<S>;

    /// Using the configuration struct, create a new `Authenticator`.
    fn make_authenticator(&self) -> Result<Self::Authenticator, crate::Error>;
}

/// Result from a successful authentication operation
#[derive(Clone, PartialEq, Debug)]
pub struct AuthenticationResult {
    /// The subject of the authentication
    pub subject: String,
    /// Additional private claims to be included in the authentication token, if any
    pub private_claims: JsonValue,
    /// The payload to be included in a Refresh token, if any
    pub refresh_payload: Option<JsonValue>,
}

#[cfg(test)]
pub mod tests {
    #[allow(deprecated)]
    use hyper::header::{self, Header, HeaderFormatter};
    use rocket::http;
    use rocket::local::Client;
    use rocket::{self, Rocket, State};

    use super::*;
    use crate::{Error, JsonMap};

    /// Mock authenticator that authenticates only the following:
    ///
    /// - Basic: user `mei` with password `冻住，不许走!`
    /// - Bearer: token `这样可以挡住他们。`
    /// - String: 哦，对不起啦。
    pub struct MockAuthenticator {}

    /// Payload for the `MockAuthenticator` Refresh Token
    #[derive(Serialize, Deserialize, Debug)]
    struct RefreshTokenPayload {
        header: String,
    }

    impl MockAuthenticator {
        /// Convert a header to string
        #[allow(deprecated)]
        fn format<S: header::Scheme + 'static>(authorization: &header::Authorization<S>) -> String {
            HeaderFormatter(authorization).to_string()
        }

        /// Generate a refresh token payload from the header
        fn serialize_refresh_token_payload<S: header::Scheme + 'static>(
            authorization: &header::Authorization<S>,
        ) -> JsonValue {
            let string = From::from(Self::format(authorization));
            let mut map = JsonMap::with_capacity(1);
            let _ = map.insert("header".to_string(), string);
            JsonValue::Object(map)
        }

        /// From a refresh token payload, get the header back
        ///
        /// # Panics
        /// Panics if the refresh token payload is not in the right shape,
        /// or if the content is invalid
        fn deserialize_refresh_token_payload<S: header::Scheme + 'static>(
            refresh_payload: &JsonValue,
        ) -> header::Authorization<S> {
            match *refresh_payload {
                JsonValue::Object(ref map) => {
                    // will panic if the shape is incorrect
                    let header = map["header"].as_str().unwrap();
                    let header = header.as_bytes().to_vec();
                    header::Authorization::parse_header(&[header]).unwrap()
                }
                _ => panic!("Refresh token payload was not a map"),
            }
        }
    }

    impl Authenticator<Basic> for MockAuthenticator {
        fn authenticate(
            &self,
            authorization: &Authorization<Basic>,
            include_refresh_payload: bool,
        ) -> Result<AuthenticationResult, Error> {
            let username = authorization.username();
            let password = authorization.password().unwrap_or_else(|| "".to_string());

            if username == "mei" && password == "冻住，不许走!" {
                let refresh_payload = if include_refresh_payload {
                    Some(Self::serialize_refresh_token_payload(authorization))
                } else {
                    None
                };
                Ok(AuthenticationResult {
                    subject: username,
                    private_claims: JsonValue::Object(JsonMap::new()),
                    refresh_payload,
                })
            } else {
                Err(super::Error::AuthenticationFailure)?
            }
        }

        fn authenticate_refresh_token(
            &self,
            refresh_payload: &JsonValue,
        ) -> Result<AuthenticationResult, Error> {
            let header: header::Authorization<Basic> =
                Self::deserialize_refresh_token_payload(refresh_payload);
            self.authenticate(&Authorization(header), false)
        }
    }

    impl Authenticator<Bearer> for MockAuthenticator {
        fn authenticate(
            &self,
            authorization: &Authorization<Bearer>,
            include_refresh_payload: bool,
        ) -> Result<AuthenticationResult, Error> {
            let token = authorization.token();

            if token == "这样可以挡住他们。" {
                let refresh_payload = if include_refresh_payload {
                    Some(Self::serialize_refresh_token_payload(authorization))
                } else {
                    None
                };
                Ok(AuthenticationResult {
                    subject: "这样可以挡住他们。".to_string(),
                    private_claims: JsonValue::Object(JsonMap::new()),
                    refresh_payload,
                })
            } else {
                Err(super::Error::AuthenticationFailure)?
            }
        }

        fn authenticate_refresh_token(
            &self,
            refresh_payload: &JsonValue,
        ) -> Result<AuthenticationResult, Error> {
            let header: header::Authorization<Bearer> =
                Self::deserialize_refresh_token_payload(refresh_payload);
            self.authenticate(&Authorization(header), false)
        }
    }

    impl Authenticator<String> for MockAuthenticator {
        fn authenticate(
            &self,
            authorization: &Authorization<String>,
            include_refresh_payload: bool,
        ) -> Result<AuthenticationResult, Error> {
            let string = authorization.string();

            if string == "哦，对不起啦。" {
                let refresh_payload = if include_refresh_payload {
                    Some(Self::serialize_refresh_token_payload(authorization))
                } else {
                    None
                };
                Ok(AuthenticationResult {
                    subject: "哦，对不起啦。".to_string(),
                    private_claims: JsonValue::Object(JsonMap::new()),
                    refresh_payload,
                })
            } else {
                Err(super::Error::AuthenticationFailure)?
            }
        }

        fn authenticate_refresh_token(
            &self,
            refresh_payload: &JsonValue,
        ) -> Result<AuthenticationResult, Error> {
            let header: header::Authorization<String> =
                Self::deserialize_refresh_token_payload(refresh_payload);
            self.authenticate(&Authorization(header), false)
        }
    }

    /// Configuration struct for `MockAuthenticator`.
    #[derive(Serialize, Deserialize, Debug)]
    pub struct MockAuthenticatorConfiguration {}

    impl<S> AuthenticatorConfiguration<S> for MockAuthenticatorConfiguration
    where
        S: header::Scheme + 'static,
        MockAuthenticator: Authenticator<S>,
    {
        type Authenticator = MockAuthenticator;

        fn make_authenticator(&self) -> Result<Self::Authenticator, Error> {
            Ok(Self::Authenticator {})
        }
    }

    /// Ignite a Rocket with a Basic authenticator
    pub fn ignite_basic(authenticator: Box<dyn Authenticator<Basic>>) -> Rocket {
        // Ignite rocket
        rocket::ignite()
            .mount("/", routes![auth_basic])
            .manage(authenticator)
    }

    #[get("/")]
    #[allow(unmounted_route)]
    #[allow(needless_pass_by_value)]
    fn auth_basic(
        authorization: Option<Authorization<Basic>>,
        authenticator: State<'_, Box<dyn Authenticator<Basic>>>,
    ) -> Result<(), Error> {
        let authorization = authorization
            .ok_or_else(|| missing_authorization::<()>("https://www.acme.com").unwrap_err())?;
        authenticator
            .prepare_authentication_response(&authorization, true)
            .and_then(|_| Ok(()))
    }

    /// Ignite a Rocket with a Bearer authenticator
    pub fn ignite_bearer(authenticator: Box<dyn Authenticator<Bearer>>) -> Rocket {
        // Ignite rocket
        rocket::ignite()
            .mount("/", routes![auth_bearer])
            .manage(authenticator)
    }

    #[get("/")]
    #[allow(unmounted_route)]
    #[allow(needless_pass_by_value)]
    fn auth_bearer(
        authorization: Option<Authorization<Bearer>>,
        authenticator: State<'_, Box<dyn Authenticator<Bearer>>>,
    ) -> Result<(), Error> {
        let authorization = authorization
            .ok_or_else(|| missing_authorization::<()>("https://www.acme.com").unwrap_err())?;
        authenticator
            .prepare_authentication_response(&authorization, true)
            .and_then(|_| Ok(()))
    }

    /// Ignite a Rocket with a String authenticator
    pub fn ignite_string(authenticator: Box<dyn Authenticator<String>>) -> Rocket {
        // Ignite rocket
        rocket::ignite()
            .mount("/", routes![auth_string])
            .manage(authenticator)
    }

    #[get("/")]
    #[allow(unmounted_route)]
    #[allow(needless_pass_by_value)]
    fn auth_string(
        authorization: Option<Authorization<String>>,
        authenticator: State<'_, Box<dyn Authenticator<String>>>,
    ) -> Result<(), Error> {
        let authorization = authorization
            .ok_or_else(|| missing_authorization::<()>("https://www.acme.com").unwrap_err())?;
        authenticator
            .prepare_authentication_response(&authorization, true)
            .and_then(|_| Ok(()))
    }

    #[test]
    #[allow(deprecated)]
    fn parses_basic_auth_correctly() {
        let auth = header::Authorization(Basic {
            username: "Aladdin".to_owned(),
            password: Some("open sesame".to_string()),
        });

        let header = HeaderFormatter(&auth).to_string();
        let parsed_header = not_err!(Authorization::new(&header));
        let Authorization(header::Authorization(Basic { username, password })) = parsed_header;
        assert_eq!(username, "Aladdin");
        assert_eq!(password, Some("open sesame".to_string()));
    }

    #[test]
    #[allow(deprecated)]
    fn parses_bearer_auth_correctly() {
        let auth = header::Authorization(Bearer {
            token: "token".to_string(),
        });
        let header = HeaderFormatter(&auth).to_string();
        let parsed_header = not_err!(Authorization::new(&header));
        let Authorization(header::Authorization(Bearer { token })) = parsed_header;
        assert_eq!(token, "token");
    }

    #[test]
    #[allow(deprecated)]
    fn parses_string_auth_correctly() {
        let auth = header::Authorization("hello".to_string());
        let header = HeaderFormatter(&auth).to_string();
        let parsed_header: Authorization<String> = not_err!(Authorization::new(&header));
        let Authorization(header::Authorization(ref s)) = parsed_header;
        assert_eq!(s, "hello");
    }

    #[test]
    #[allow(deprecated)]
    fn mock_basic_auth_get_test() {
        let rocket = ignite_basic(Box::new(MockAuthenticator {}));
        let client = not_err!(Client::new(rocket));

        // Make headers
        let auth_header = hyper::header::Authorization(Basic {
            username: "mei".to_owned(),
            password: Some("冻住，不许走!".to_string()),
        });
        let auth_header =
            http::Header::new("Authorization", HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let req = client.get("/").header(auth_header);
        let response = req.dispatch();

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    #[allow(deprecated)]
    fn mock_bearer_auth_get_test() {
        let rocket = ignite_bearer(Box::new(MockAuthenticator {}));
        let client = not_err!(Client::new(rocket));

        // Make headers
        let auth_header = hyper::header::Authorization(Bearer {
            token: "这样可以挡住他们。".to_string(),
        });
        let auth_header =
            http::Header::new("Authorization", HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let req = client.get("/").header(auth_header);
        let response = req.dispatch();

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    #[allow(deprecated)]
    fn mock_string_auth_get_test() {
        let rocket = ignite_string(Box::new(MockAuthenticator {}));
        let client = not_err!(Client::new(rocket));

        // Make headers
        let auth_header = hyper::header::Authorization("哦，对不起啦。".to_string());
        let auth_header =
            http::Header::new("Authorization", HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let req = client.get("/").header(auth_header);
        let response = req.dispatch();

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    #[allow(deprecated)]
    fn mock_basic_auth_get_invalid_credentials() {
        // Ignite rocket
        let rocket = ignite_basic(Box::new(MockAuthenticator {}));
        let client = not_err!(Client::new(rocket));

        // Make headers
        let auth_header = hyper::header::Authorization(Basic {
            username: "Aladin".to_owned(),
            password: Some("let me in".to_string()),
        });
        let auth_header =
            http::Header::new("Authorization", HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let req = client.get("/").header(auth_header);
        let response = req.dispatch();

        // Assert
        assert_eq!(response.status(), Status::Unauthorized);
    }

    #[test]
    #[allow(deprecated)]
    fn mock_bearer_auth_get_invalid_credentials() {
        // Ignite rocket
        let rocket = ignite_bearer(Box::new(MockAuthenticator {}));
        let client = not_err!(Client::new(rocket));

        // Make headers
        let auth_header = hyper::header::Authorization(Bearer {
            token: "bad".to_string(),
        });
        let auth_header =
            http::Header::new("Authorization", HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let req = client.get("/").header(auth_header);
        let response = req.dispatch();

        // Assert
        assert_eq!(response.status(), Status::Unauthorized);
    }

    #[test]
    #[allow(deprecated)]
    fn mock_string_auth_get_invalid_credentials() {
        // Ignite rocket
        let rocket = ignite_string(Box::new(MockAuthenticator {}));
        let client = not_err!(Client::new(rocket));

        // Make headers
        let auth_header = hyper::header::Authorization("bad".to_string());
        let auth_header =
            http::Header::new("Authorization", HeaderFormatter(&auth_header).to_string());
        // Make and dispatch request
        let req = client.get("/").header(auth_header);
        let response = req.dispatch();

        // Assert
        assert_eq!(response.status(), Status::Unauthorized);
    }

    #[test]
    #[allow(deprecated)]
    fn mock_basic_auth_get_missing_credentials() {
        // Ignite rocket
        let rocket = ignite_basic(Box::new(MockAuthenticator {}));
        let client = not_err!(Client::new(rocket));

        // Make and dispatch request
        let req = client.get("/");
        let response = req.dispatch();

        // Assert
        assert_eq!(response.status(), Status::Unauthorized);

        let www_header: Vec<_> = response.headers().get("WWW-Authenticate").collect();
        assert_eq!(www_header, vec!["Basic realm=https://www.acme.com"]);
    }
}
