//! Authentication
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

#[cfg(feature = "simple_authenticator")]
mod simple;
#[cfg(feature = "simple_authenticator")]
pub use self::simple::SimpleAuthenticator;

pub type BasicAuthenticator = Authenticator<hyper::header::Basic>;
pub type BearerAuthenticator = Authenticator<hyper::header::Bearer>;
pub type StringAuthenticator = Authenticator<String>;

/// Authentication errors
#[derive(Debug)]
pub enum Error {
    AuthenticationFailure,
    GenericError(String),
    HyperError(hyper::error::Error),
    MissingAuthorization { realm: String },
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

impl Authorization<header::Basic> {
    pub fn username(&self) -> String {
        let Authorization(header::Authorization(header::Basic { ref username, .. })) = *self;
        username.to_string()
    }

    pub fn password(&self) -> Option<String> {
        let Authorization(header::Authorization(header::Basic { ref password, .. })) = *self;
        password.clone()
    }
}

impl Authorization<header::Bearer> {
    pub fn token(&self) -> String {
        let Authorization(header::Authorization(header::Bearer { ref token })) = *self;
        token.to_string()
    }
}

impl Authorization<String> {
    pub fn string(&self) -> String {
        let Authorization(header::Authorization(ref s)) = *self;
        s.to_string()
    }
}

/// Authenticator trait which will be used to authenticate users
// XXX: Assocaited type or generic? https://stackoverflow.com/questions/32059370/
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

/// A "no-op" authenticator that lets everything through
pub struct NoOp {}

impl<S: header::Scheme + 'static> Authenticator<S> for NoOp {
    fn authenticate(&self, _authorization: &Authorization<S>) -> Result<(), Error> {
        Ok(())
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

    impl super::Authenticator<header::Basic> for MockAuthenticator {
        fn authenticate(&self, authorization: &Authorization<header::Basic>) -> Result<(), Error> {
            let username = authorization.username();
            let password = authorization.password().unwrap_or_else(|| "".to_string());

            if username == "mei" && password == "冻住，不许走!" {
                Ok(())
            } else {
                Err(Error::AuthenticationFailure)
            }
        }
    }

    impl super::Authenticator<header::Bearer> for MockAuthenticator {
        fn authenticate(&self, authorization: &Authorization<header::Bearer>) -> Result<(), Error> {
            let token = authorization.token();

            if token == "这样可以挡住他们。" {
                Ok(())
            } else {
                Err(Error::AuthenticationFailure)
            }
        }
    }

    impl super::Authenticator<String> for MockAuthenticator {
        fn authenticate(&self, authorization: &Authorization<String>) -> Result<(), Error> {
            let string = authorization.string();

            if string == "哦，对不起啦。" {
                Ok(())
            } else {
                Err(Error::AuthenticationFailure)
            }
        }
    }

    fn ignite_basic(authenticator: Box<Authenticator<header::Basic>>) -> Rocket {
        // Ignite rocket
        rocket::ignite().mount("/", routes![auth_basic]).manage(authenticator)
    }

    #[get("/")]
    #[allow(unmounted_route)]
    #[allow(needless_pass_by_value)]
    fn auth_basic(authorization: Option<Authorization<header::Basic>>,
                  authenticator: State<Box<Authenticator<header::Basic>>>)
                  -> Result<(), ::Error> {

        authenticator.prepare_response("https://www.acme.com", authorization).and_then(|_| Ok(()))
    }

    fn ignite_bearer(authenticator: Box<Authenticator<header::Bearer>>) -> Rocket {
        // Ignite rocket
        rocket::ignite().mount("/", routes![auth_bearer]).manage(authenticator)
    }

    #[get("/")]
    #[allow(unmounted_route)]
    #[allow(needless_pass_by_value)]
    fn auth_bearer(authorization: Option<Authorization<header::Bearer>>,
                   authenticator: State<Box<Authenticator<header::Bearer>>>)
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
        let auth = header::Authorization(header::Basic {
                                             username: "Aladdin".to_owned(),
                                             password: Some("open sesame".to_string()),
                                         });
        let mut request = Request::new(rocket::http::Method::Get, "/");
        let header = rocket::http::Header::new(header::Authorization::<header::Basic>::header_name(),
                                               format!("{}", HeaderFormatter(&auth)));
        request.add_header(header);
        let outcome: request::Outcome<::auth::Authorization<header::Basic>, ::auth::Error> =
            FromRequest::from_request(&request);

        let parsed_header = assert_matches!(outcome, Outcome::Success(s), s);
        let ::auth::Authorization(header::Authorization(header::Basic { username, password })) = parsed_header;
        assert_eq!(username, "Aladdin");
        assert_eq!(password, Some("open sesame".to_string()));
    }

    #[test]
    #[allow(deprecated)]
    fn parses_bearer_auth_correctly() {
        let auth = header::Authorization(header::Bearer { token: "token".to_string() });
        let mut request = Request::new(rocket::http::Method::Get, "/");
        let header = rocket::http::Header::new(header::Authorization::<header::Bearer>::header_name(),
                                               format!("{}", HeaderFormatter(&auth)));
        request.add_header(header);
        let outcome: request::Outcome<::auth::Authorization<header::Bearer>, ::auth::Error> =
            FromRequest::from_request(&request);

        let parsed_header = assert_matches!(outcome, Outcome::Success(s), s);
        let ::auth::Authorization(header::Authorization(header::Bearer { token })) = parsed_header;
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
        let auth_header = hyper::header::Authorization(hyper::header::Basic {
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
            hyper::header::Authorization(hyper::header::Bearer { token: "这样可以挡住他们。".to_string() });
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
        let auth_header = hyper::header::Authorization(hyper::header::Basic {
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
        let auth_header = hyper::header::Authorization(hyper::header::Bearer { token: "bad".to_string() });
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
        let auth_header = hyper::header::Authorization(hyper::header::Basic {
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
        let auth_header = hyper::header::Authorization(hyper::header::Bearer { token: "foobar".to_string() });
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
