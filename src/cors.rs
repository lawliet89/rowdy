//! Cross-origin resource sharing
//!
//! Rocket (as of v0.2.2) does not have middleware support. Support for it is (supposedly)
//! on the way. In the mean time, we adopt an
//! [example implementation](https://github.com/SergioBenitez/Rocket/pull/141) to nest `Responders` to acheive
//! the same effect in the short run.
use std::collections::HashSet;
use std::error;
use std::fmt;
use std::str::FromStr;

use hyper::Url;
use hyper::error::ParseError;
use rocket::request::{self, Request, FromRequest};
use rocket::response::{self, Response, Responder};
use rocket::http::{Method, Status};
use rocket::Outcome;

// TODO: impl Responder?
#[derive(Debug)]
pub enum Error {
    MissingOrigin,
    BadOrigin(ParseError),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::MissingOrigin => "The request header `Origin` is required but is missing",
            Error::BadOrigin(_) => "The request header `Origin` contains an invalid URL",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::BadOrigin(ref e) => Some(e as &error::Error),
            _ => Some(self as &error::Error),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::BadOrigin(ref e) => fmt::Display::fmt(e, f),
            _ => write!(f, "{}", error::Error::description(self)),
        }
    }
}

/// The `Origin` header used in CORS
pub struct Origin(Url);

impl FromStr for Origin {
    type Err = ParseError;

    fn from_str(url: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(url)?;
        Ok(Origin(url))
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for Origin {
    type Error = Error;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Origin, Error> {
        match request.headers().get_one("Origin") {
            Some(origin) => {
                match Origin::from_str(origin) {
                    Ok(origin) => Outcome::Success(origin),
                    Err(e) => Outcome::Failure((Status::BadRequest, Error::BadOrigin(e))),
                }
            }
            None => Outcome::Failure((Status::BadRequest, Error::MissingOrigin)),
        }
    }
}

/// The `Access-Control-Request-Method` header
pub struct AccessControlRequestMethod(Method);

/// The `Access-Control-Request-Headers`
pub struct AccessControlRequestHeaders(HashSet<String>);


/// The CORS type, which implements `Responder`. This type allows
/// you to request resources from another domain.
pub struct CORS<R> {
    responder: R,
    allow_origin: String,
    allow_credentials: bool,
    expose_headers: HashSet<String>,
    max_age: Option<usize>,
    allow_methods: HashSet<Method>,
    allow_headers: HashSet<String>,
}

// pub type PreflightCORS = CORS<()>;

// impl PreflightCORS {
//     /// Consumes origin for which it will allow to use `CORS`
//     /// and return a basic origin `CORS`
//     pub fn preflight(origin: &'static str) -> PreflightCORS {
//         CORS::origin((), origin)
//     }
// }

impl<'r, R: Responder<'r>> CORS<R> {
    /// Consumes responder and returns CORS with any origin
    pub fn any(responder: R) -> CORS<R> {
        CORS::origin(responder, "*")
    }

    /// Consumes the responder and origin and returns basic CORS
    pub fn origin(responder: R, origin: &str) -> CORS<R> {
        CORS {
            responder: responder,
            allow_origin: origin.to_string(),
            allow_credentials: false,
            expose_headers: HashSet::new(),
            max_age: None,
            allow_methods: HashSet::new(),
            allow_headers: HashSet::new(),
        }
    }

    /// Consumes the CORS, set allow_credentials to
    /// new value and returns changed CORS
    pub fn credentials(mut self, value: bool) -> CORS<R> {
        self.allow_credentials = value;
        self
    }

    /// Consumes the CORS, set expose_headers to
    /// passed headers and returns changed CORS
    pub fn exposed_headers(mut self, headers: &[&str]) -> CORS<R> {
        self.expose_headers = headers.into_iter().map(|s| s.to_string()).collect();
        self
    }

    /// Consumes the CORS, set max_age to
    /// passed value and returns changed CORS
    pub fn max_age(mut self, value: Option<usize>) -> CORS<R> {
        self.max_age = value;
        self
    }

    /// Consumes the CORS, set allow_methods to
    /// passed methods and returns changed CORS
    pub fn methods(mut self, methods: &[Method]) -> CORS<R> {
        self.allow_methods = methods.into_iter().cloned().collect();
        self
    }

    /// Consumes the CORS, set allow_headers to
    /// passed headers and returns changed CORS
    pub fn headers(mut self, headers: &[&str]) -> CORS<R> {
        self.allow_headers = headers.into_iter().map(|s| s.to_string()).collect();
        self
    }
}

impl<'r, R: Responder<'r>> Responder<'r> for CORS<R> {
    fn respond(self) -> response::Result<'r> {
        let mut response = Response::build_from(self.responder.respond()?)
            .raw_header("Access-Control-Allow-Origin", self.allow_origin)
            .finalize();

        if self.allow_credentials {
            response.set_raw_header("Access-Control-Allow-Credentials", "true");
        } else {
            response.set_raw_header("Access-Control-Allow-Credentials", "false");
        }

        if !self.expose_headers.is_empty() {
            let headers: Vec<_> = self.expose_headers.into_iter().collect();
            let headers = headers.join(", ");

            response.set_raw_header("Access-Control-Expose-Headers", headers);
        }

        if !self.allow_methods.is_empty() {
            let methods: Vec<_> = self.allow_methods
                .into_iter()
                .map(|m| m.as_str())
                .collect();
            let methods = methods.join(", ");

            response.set_raw_header("Access-Control-Allow-Methods", methods);
        }

        if self.max_age.is_some() {
            let max_age = self.max_age.unwrap();
            response.set_raw_header("Access-Control-Max-Age", max_age.to_string());
        }

        Ok(response)
    }
}

#[cfg(test)]
#[allow(unmounted_route)]
mod tests {
    use rocket;
    use rocket::testing::MockRequest;
    use rocket::http::Method::*;
    use rocket::http::Header;

    use cors;

    #[get("/hello")]
    fn hello() -> cors::CORS<&'static str> {
        cors::CORS::any("Hello, world!")
    }

    #[get("/request_headers")]
    fn request_headers(origin: cors::Origin) -> cors::CORS<String> {
        let cors::Origin(origin) = origin;
        cors::CORS::any(origin.into_string())
    }

    #[test]
    fn smoke_test() {
        let rocket = rocket::ignite().mount("/", routes![hello]);
        let mut req = MockRequest::new(Get, "/hello");
        let mut response = req.dispatch_with(&rocket);

        let body_str = response.body().and_then(|body| body.into_string());
        let values: Vec<_> = response.header_values("Access-Control-Allow-Origin").collect();
        assert_eq!(values, vec!["*"]);
        assert_eq!(body_str, Some("Hello, world!".to_string()));
    }

    #[test]
    fn request_headers_smoke_test() {
        let rocket = rocket::ignite().mount("/", routes![request_headers]);
        let origin_header = Header::new("Origin", "https://foo.bar.xyz");
        let mut req = MockRequest::new(Get, "/request_headers").header(origin_header);
        let mut response = req.dispatch_with(&rocket);

        let body_str = not_none!(response.body().and_then(|body| body.into_string()));
        println!("{}", body_str);
    }
}
