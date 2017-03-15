//! Authentication
use std::convert::From;
use std::error;
use std::fmt;

use hyper;
use hyper::header;
use rocket::http::Status;
use rocket::request::{self, Request, FromRequest};
use rocket::response::{self, Responder};
use rocket::Outcome;

#[derive(Debug)]
pub enum Error {
    MissingAuthorization,
    HyperError(hyper::error::Error),
}
impl_from_error!(hyper::error::Error, Error::HyperError);

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::MissingAuthorization => "The request header `Authorization` is required but is missing",
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

impl<'r> Responder<'r> for Error {
    fn respond(self) -> Result<response::Response<'r>, Status> {
        error_!("Headers Error: {:?}", self);
        Err(match self {
                Error::MissingAuthorization => Status::Forbidden,
                Error::HyperError(_) => Status::BadRequest,
            })
    }
}

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
            None => Outcome::Failure((Status::Forbidden, Error::MissingAuthorization)),
        }
    }
}

// TODO: Proper authentication responder, wrapped around like CORS
// TODO: Send `WWW-Authenticate` header on missing auth instead of a simple 403
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate

#[cfg(test)]
mod tests {
    #[allow(deprecated)]
    use hyper::header::{self, Header, HeaderFormatter};
    use rocket::{self, Outcome};
    use rocket::request::{self, Request, FromRequest};

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
}
