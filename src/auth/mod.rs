//! Authentication module, including traits for identity provider and `Responder`s for authentication.
use std::convert::From;
use std::error;
use std::fmt;

use hyper;
use hyper::header;
use rocket;
use rocket::http::Status;
use rocket::request::{self, Request, FromRequest};
use rocket::response;
use rocket::Outcome;
use serde::{Serialize, Deserialize};

#[cfg(feature = "simple_authenticator")]
mod simple;
#[cfg(feature = "simple_authenticator")]
pub use self::simple::SimpleAuthenticator;
#[cfg(feature = "simple_authenticator")]
pub use self::simple::SimpleAuthenticatorConfiguration;

/// Re-exported [`hyper::header::Scheme`]
pub type Scheme = hyper::header::Scheme<Err = hyper::error::Error>;
/// Re-exported [`hyper::header::Basic`].
pub type Basic = hyper::header::Basic;
/// Re-exported [`hyper::header::Bearer`].
pub type Bearer = hyper::header::Bearer;

/// A typedef for an `Authenticator` trait object that requires HTTP Basic authentication
pub type BasicAuthenticator = Authenticator<Basic>;
/// A typedef for an `Authenticator` trait object that requires Bearer authentication.
pub type BearerAuthenticator = Authenticator<Bearer>;
/// A typedef for an `Authenticator` trait object that uses an arbitrary string
pub type StringAuthenticator = Authenticator<String>;

/// Authentication errors
#[derive(Debug)]
pub enum Error {
    /// Authentication was attempted successfully, but failed because of bad user credentials, or other reasons.
    AuthenticationFailure,
    /// A generic error
    GenericError(String),
    /// An error due to `hyper`, such as header parsing failure
    HyperError(hyper::error::Error),
    /// The `Authorization` HTTP request header was required but was missing. This variant will `respond` with the
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
            Error::MissingAuthorization { .. } => "The request header `Authorization` is required but is missing",
            Error::GenericError(ref e) => &**e,
            Error::HyperError(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::HyperError(ref e) => Some(e as &error::Error),
            _ => Some(self as &error::Error),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::HyperError(ref e) => fmt::Display::fmt(e, f),
            _ => write!(f, "{}", error::Error::description(self)),
        }
    }
}

impl<'r> response::Responder<'r> for Error {
    fn respond(self) -> Result<response::Response<'r>, Status> {
        error_!("Headers Error: {:?}", self);
        match self {
            Error::MissingAuthorization { ref realm } => {
                // TODO: Support other schemes!
                let www_header = rocket::http::Header::new("WWW-Authenticate", format!("Basic realm={}", realm));

                Ok(response::Response::build().status(Status::Unauthorized).header(www_header).finalize())
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
        use hyper::header::Header;

        match request.headers().get_one("Authorization") {
            Some(authorization) => {
                let bytes: Vec<u8> = authorization.as_bytes().to_vec();
                match header::Authorization::parse_header(&[bytes]) {
                    Err(e) => Outcome::Failure((Status::BadRequest, From::from(e))),
                    Ok(parsed) => Outcome::Success(Authorization(parsed)),
                }

            }
            None => Outcome::Forward(()),
        }
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

/// Authenticator trait to be implemented by identity provider (idp) adapters to provide authentication.
/// Each idp may support all the [schemes](https://hyper.rs/hyper/v0.10.5/hyper/header/trait.Scheme.html)
/// supported, or just one.
///
/// Usually, you will want to include an `Authenticator` trait object as part of Rocket's
/// [managed state](https://rocket.rs/guide/state/). Before you can do that, however, you will need to `Box` it up.
/// See example below.
///
/// # Examples
/// Consider the following mock authenticator that authenticates only the following:
///
/// - Basic: User `mei` with password `冻住，不许走!`
/// - Bearer: Token `这样可以挡住他们。`
/// - String: `哦，对不起啦。`
///
/// After defining the authenticator, the example will show how it can be used in a route.
///
/// ```
/// #![feature(plugin, custom_derive)]
/// #![plugin(rocket_codegen)]
/// extern crate hyper;
/// extern crate rocket;
/// extern crate rowdy;
///
/// use hyper::header;
/// use rocket::{State, Rocket};
/// use rocket::http::{self, Status};
/// use rocket::http::Method::Get;
/// use rocket::testing::MockRequest;
/// use rowdy::auth::*;
/// pub struct MockAuthenticator {}
///
/// impl Authenticator<Basic> for MockAuthenticator {
///     fn authenticate(&self, authorization: &Authorization<Basic>) -> Result<(), Error> {
///         let username = authorization.username();
///         let password = authorization.password().unwrap_or_else(|| "".to_string());
///
///         if username == "mei" && password == "冻住，不许走!" {
///             Ok(())
///         } else {
///             Err(Error::AuthenticationFailure)
///         }
///     }
/// }
///
/// impl Authenticator<Bearer> for MockAuthenticator {
///     fn authenticate(&self, authorization: &Authorization<Bearer>) -> Result<(), Error> {
///         let token = authorization.token();
///
///         if token == "这样可以挡住他们。" {
///             Ok(())
///         } else {
///             Err(Error::AuthenticationFailure)
///         }
///     }
/// }
///
/// impl Authenticator<String> for MockAuthenticator {
///     fn authenticate(&self, authorization: &Authorization<String>) -> Result<(), Error> {
///         let string = authorization.string();
///
///         if string == "哦，对不起啦。" {
///             Ok(())
///         } else {
///             Err(Error::AuthenticationFailure)
///         }
///     }
/// }
/// #[get("/")]
/// #[allow(unmounted_route)]
/// fn auth_basic(authorization: Option<Authorization<Basic>>,
///               authenticator: State<Box<Authenticator<Basic>>>)
///               -> Result<&str, rowdy::Error> {
///
///     authenticator.prepare_response("https://www.acme.com", authorization)
///         .and_then(|_| Ok("Hello world"))
/// }
///
/// fn ignite_basic(authenticator: Box<Authenticator<Basic>>) -> Rocket {
///     // Ignite rocket
///     rocket::ignite().mount("/", routes![auth_basic]).manage(authenticator)
/// }
///
/// # #[allow(deprecated)]
/// # fn main() {
/// let rocket = ignite_basic(Box::new(MockAuthenticator {}));
/// let auth_header = hyper::header::Authorization(Basic {
///                                                     username: "mei".to_owned(),
///                                                     password: Some("冻住，不许走!".to_string()),
///                                                 });
/// let auth_header = http::Header::new("Authorization",
///                                     format!("{}", hyper::header::HeaderFormatter(&auth_header)));
/// // Make and dispatch request
/// let mut req = MockRequest::new(Get, "/").header(auth_header);
/// let response = req.dispatch_with(&rocket);
///
/// assert_eq!(response.status(), Status::Ok);
/// # }
/// ```
pub trait Authenticator<S: header::Scheme + 'static>: Send + Sync {
    /// Verify the credentials provided in the headers with the authenticator. Not usually called by users.
    /// Use `prepare_response` instead.
    fn authenticate(&self, authorization: &Authorization<S>) -> Result<(), Error>;

    /// Prepare a response by first verifying credentials. If validation fails, will return an `Err` with the response
    /// to be sent. Otherwise, the unwrapped credentials will be returned in an `Ok`.
    fn prepare_response(&self,
                        realm: &str,
                        authorization: Option<Authorization<S>>)
                        -> Result<Authorization<S>, ::Error> {
        match authorization {
            None => Err(Error::MissingAuthorization { realm: realm.to_string() })?,
            Some(credentials) => Ok(self.authenticate(&credentials).map(|()| credentials)?),
        }
    }
}
/// Configuration for the associated type `Authenticator`. [`rowdy::Configuration`] expects its `authenticator` field
/// to implement this trait. Before launching, `rowdy` will attempt to make an `Authenticator` based off the
/// configuration by calling the `make_authenticator` method.
pub trait AuthenticatorConfiguration<S: header::Scheme + 'static>
    : Send + Sync + Serialize + Deserialize + 'static {
    /// The `Authenticator` type this configuration is associated with
    type Authenticator: Authenticator<S>;

    /// Using the configuration struct, create a new `Authenticator`.
    fn make_authenticator(&self) -> Result<Self::Authenticator, ::Error>;
}

/// A "no-op" authenticator that lets everything through
#[derive(Debug)]
pub struct NoOp {}

impl<S: header::Scheme + 'static> Authenticator<S> for NoOp {
    fn authenticate(&self, _authorization: &Authorization<S>) -> Result<(), Error> {
        Ok(())
    }
}

/// Configuration for the `no-op` authenticator. Nothing to configure.
#[derive(Serialize, Deserialize, Debug)]
pub struct NoOpConfiguration {}

impl<S: header::Scheme + 'static> AuthenticatorConfiguration<S> for NoOpConfiguration {
    type Authenticator = NoOp;

    fn make_authenticator(&self) -> Result<Self::Authenticator, ::Error> {
        Ok(Self::Authenticator {})
    }
}

#[cfg(test)]
pub mod tests {
    #[allow(deprecated)]
    use hyper::header::{self, Header, HeaderFormatter};
    use rocket::{self, Outcome, State, Rocket};
    use rocket::http;
    use rocket::http::Method::Get;
    use rocket::request::{self, Request, FromRequest};
    use rocket::testing::MockRequest;

    use super::*;

    /// Mock authenticator that authenticates only the following:
    ///
    /// - Basic: user `mei` with password `冻住，不许走!`
    /// - Bearer: token `这样可以挡住他们。`
    /// - String: 哦，对不起啦。
    pub struct MockAuthenticator {}

    impl Authenticator<Basic> for MockAuthenticator {
        fn authenticate(&self, authorization: &Authorization<Basic>) -> Result<(), Error> {
            let username = authorization.username();
            let password = authorization.password().unwrap_or_else(|| "".to_string());

            if username == "mei" && password == "冻住，不许走!" {
                Ok(())
            } else {
                Err(Error::AuthenticationFailure)
            }
        }
    }

    impl Authenticator<Bearer> for MockAuthenticator {
        fn authenticate(&self, authorization: &Authorization<Bearer>) -> Result<(), Error> {
            let token = authorization.token();

            if token == "这样可以挡住他们。" {
                Ok(())
            } else {
                Err(Error::AuthenticationFailure)
            }
        }
    }

    impl Authenticator<String> for MockAuthenticator {
        fn authenticate(&self, authorization: &Authorization<String>) -> Result<(), Error> {
            let string = authorization.string();

            if string == "哦，对不起啦。" {
                Ok(())
            } else {
                Err(Error::AuthenticationFailure)
            }
        }
    }

    /// Configuration struct for `MockAuthenticator`.
    #[derive(Serialize, Deserialize, Debug)]
    pub struct MockAuthenticatorConfiguration {}

    impl<S: header::Scheme + 'static> AuthenticatorConfiguration<S> for MockAuthenticatorConfiguration
        where MockAuthenticator: Authenticator<S>
    {
        type Authenticator = MockAuthenticator;

        fn make_authenticator(&self) -> Result<Self::Authenticator, ::Error> {
            Ok(Self::Authenticator {})
        }
    }

    fn ignite_basic(authenticator: Box<Authenticator<Basic>>) -> Rocket {
        // Ignite rocket
        rocket::ignite().mount("/", routes![auth_basic]).manage(authenticator)
    }

    #[get("/")]
    #[allow(unmounted_route)]
    #[allow(needless_pass_by_value)]
    fn auth_basic(authorization: Option<Authorization<Basic>>,
                  authenticator: State<Box<Authenticator<Basic>>>)
                  -> Result<(), ::Error> {

        authenticator.prepare_response("https://www.acme.com", authorization).and_then(|_| Ok(()))
    }

    fn ignite_bearer(authenticator: Box<Authenticator<Bearer>>) -> Rocket {
        // Ignite rocket
        rocket::ignite().mount("/", routes![auth_bearer]).manage(authenticator)
    }

    #[get("/")]
    #[allow(unmounted_route)]
    #[allow(needless_pass_by_value)]
    fn auth_bearer(authorization: Option<Authorization<Bearer>>,
                   authenticator: State<Box<Authenticator<Bearer>>>)
                   -> Result<(), ::Error> {

        authenticator.prepare_response("https://www.acme.com", authorization).and_then(|_| Ok(()))
    }

    fn ignite_string(authenticator: Box<Authenticator<String>>) -> Rocket {
        // Ignite rocket
        rocket::ignite().mount("/", routes![auth_string]).manage(authenticator)
    }

    #[get("/")]
    #[allow(unmounted_route)]
    #[allow(needless_pass_by_value)]
    fn auth_string(authorization: Option<Authorization<String>>,
                   authenticator: State<Box<Authenticator<String>>>)
                   -> Result<(), ::Error> {

        authenticator.prepare_response("https://www.acme.com", authorization).and_then(|_| Ok(()))
    }

    #[test]
    #[allow(deprecated)]
    fn parses_basic_auth_correctly() {
        let auth = header::Authorization(Basic {
                                             username: "Aladdin".to_owned(),
                                             password: Some("open sesame".to_string()),
                                         });
        let mut request = Request::new(rocket::http::Method::Get, "/");
        let header = rocket::http::Header::new(header::Authorization::<Basic>::header_name(),
                                               format!("{}", HeaderFormatter(&auth)));
        request.add_header(header);
        let outcome: request::Outcome<::auth::Authorization<Basic>, ::auth::Error> =
            FromRequest::from_request(&request);

        let parsed_header = assert_matches!(outcome, Outcome::Success(s), s);
        let ::auth::Authorization(header::Authorization(Basic { username, password })) = parsed_header;
        assert_eq!(username, "Aladdin");
        assert_eq!(password, Some("open sesame".to_string()));
    }

    #[test]
    #[allow(deprecated)]
    fn parses_bearer_auth_correctly() {
        let auth = header::Authorization(Bearer { token: "token".to_string() });
        let mut request = Request::new(rocket::http::Method::Get, "/");
        let header = rocket::http::Header::new(header::Authorization::<Bearer>::header_name(),
                                               format!("{}", HeaderFormatter(&auth)));
        request.add_header(header);
        let outcome: request::Outcome<::auth::Authorization<Bearer>, ::auth::Error> =
            FromRequest::from_request(&request);

        let parsed_header = assert_matches!(outcome, Outcome::Success(s), s);
        let ::auth::Authorization(header::Authorization(Bearer { token })) = parsed_header;
        assert_eq!(token, "token");
    }

    #[test]
    #[allow(deprecated)]
    fn parses_string_auth_correctly() {
        let auth = header::Authorization("hello".to_string());
        let mut request = Request::new(rocket::http::Method::Get, "/");
        let header = rocket::http::Header::new(header::Authorization::<String>::header_name(),
                                               format!("{}", HeaderFormatter(&auth)));
        request.add_header(header);
        let outcome: request::Outcome<::auth::Authorization<String>, ::auth::Error> =
            FromRequest::from_request(&request);

        let parsed_header = assert_matches!(outcome, Outcome::Success(s), s);
        let ::auth::Authorization(header::Authorization(ref s)) = parsed_header;
        assert_eq!(s, "hello");
    }

    #[test]
    #[allow(deprecated)]
    fn mock_basic_auth_get_test() {
        let rocket = ignite_basic(Box::new(MockAuthenticator {}));

        // Make headers
        let auth_header = hyper::header::Authorization(Basic {
                                                           username: "mei".to_owned(),
                                                           password: Some("冻住，不许走!".to_string()),
                                                       });
        let auth_header = http::Header::new("Authorization",
                                            format!("{}", hyper::header::HeaderFormatter(&auth_header)));
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/").header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    #[allow(deprecated)]
    fn mock_bearer_auth_get_test() {
        let rocket = ignite_bearer(Box::new(MockAuthenticator {}));

        // Make headers
        let auth_header =
            hyper::header::Authorization(Bearer { token: "这样可以挡住他们。".to_string() });
        let auth_header = http::Header::new("Authorization",
                                            format!("{}", hyper::header::HeaderFormatter(&auth_header)));
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/").header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    #[allow(deprecated)]
    fn mock_string_auth_get_test() {
        let rocket = ignite_string(Box::new(MockAuthenticator {}));

        // Make headers
        let auth_header = hyper::header::Authorization("哦，对不起啦。".to_string());
        let auth_header = http::Header::new("Authorization",
                                            format!("{}", hyper::header::HeaderFormatter(&auth_header)));
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/").header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    #[allow(deprecated)]
    fn mock_basic_auth_get_invalid_credentials() {
        // Ignite rocket
        let rocket = ignite_basic(Box::new(MockAuthenticator {}));

        // Make headers
        let auth_header = hyper::header::Authorization(Basic {
                                                           username: "Aladin".to_owned(),
                                                           password: Some("let me in".to_string()),
                                                       });
        let auth_header = http::Header::new("Authorization",
                                            format!("{}", hyper::header::HeaderFormatter(&auth_header)));
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/").header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Unauthorized);
    }

    #[test]
    #[allow(deprecated)]
    fn mock_bearer_auth_get_invalid_credentials() {
        // Ignite rocket
        let rocket = ignite_bearer(Box::new(MockAuthenticator {}));

        // Make headers
        let auth_header = hyper::header::Authorization(Bearer { token: "bad".to_string() });
        let auth_header = http::Header::new("Authorization",
                                            format!("{}", hyper::header::HeaderFormatter(&auth_header)));
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/").header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Unauthorized);
    }

    #[test]
    #[allow(deprecated)]
    fn mock_string_auth_get_invalid_credentials() {
        // Ignite rocket
        let rocket = ignite_string(Box::new(MockAuthenticator {}));

        // Make headers
        let auth_header = hyper::header::Authorization("bad".to_string());
        let auth_header = http::Header::new("Authorization",
                                            format!("{}", hyper::header::HeaderFormatter(&auth_header)));
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/").header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Unauthorized);
    }

    #[test]
    #[allow(deprecated)]
    fn mock_basic_auth_get_missing_credentials() {
        // Ignite rocket
        let rocket = ignite_basic(Box::new(MockAuthenticator {}));

        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/");
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Unauthorized);

        let www_header: Vec<_> = response.header_values("WWW-Authenticate").collect();
        assert_eq!(www_header, vec!["Basic realm=https://www.acme.com"]);
    }

    #[test]
    #[allow(deprecated)]
    fn noop_basic_auth_get_test() {
        let rocket = ignite_basic(Box::new(NoOp {}));

        // Make headers
        let auth_header = hyper::header::Authorization(Basic {
                                                           username: "anything".to_owned(),
                                                           password: Some("let me in".to_string()),
                                                       });
        let auth_header = http::Header::new("Authorization",
                                            format!("{}", hyper::header::HeaderFormatter(&auth_header)));
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/").header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    #[allow(deprecated)]
    fn noop_bearer_auth_get_test() {
        let rocket = ignite_bearer(Box::new(NoOp {}));

        // Make headers
        let auth_header = hyper::header::Authorization(Bearer { token: "foobar".to_string() });
        let auth_header = http::Header::new("Authorization",
                                            format!("{}", hyper::header::HeaderFormatter(&auth_header)));
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/").header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    #[allow(deprecated)]
    fn noop_string_auth_get_test() {
        let rocket = ignite_string(Box::new(NoOp {}));

        // Make headers
        let auth_header = hyper::header::Authorization("anything goes".to_string());
        let auth_header = http::Header::new("Authorization",
                                            format!("{}", hyper::header::HeaderFormatter(&auth_header)));
        // Make and dispatch request
        let mut req = MockRequest::new(Get, "/").header(auth_header);
        let response = req.dispatch_with(&rocket);

        // Assert
        assert_eq!(response.status(), Status::Ok);
    }
}
