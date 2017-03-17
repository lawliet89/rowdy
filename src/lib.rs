//! # rowdy
//!
//! `rowdy` is a JSON Web token based authentication server based off Docker Registry's
//! [authentication protocol](https://docs.docker.com/registry/spec/auth/).
//!
//! ## Features
//!
//! - `clippy_lints`: Enable clippy lints during builds
//! - `simple_authenticator`: A simple CSV based authenticator
//!
//! By default, the `simple_authenticator` feature is turned on.

#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]
#![cfg_attr(feature="clippy_lints", plugin(clippy))]

#![warn(missing_docs)]
#![doc(test(attr(allow(unused_variables), deny(warnings))))]

extern crate chrono;
extern crate hyper;
extern crate jwt;
#[macro_use]
extern crate log;
#[macro_use]
extern crate rocket; // we are using the "log_!" macros which are redefined from `log`'s
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate unicase;
extern crate uuid;

#[cfg(feature = "simple_authenticator")]
extern crate csv;
#[cfg(feature = "simple_authenticator")]
extern crate ring;

#[cfg(test)]
extern crate serde_test;

#[macro_use]
mod macros;
#[cfg(test)]
#[macro_use]
mod test;
pub mod auth;
pub mod cors;
mod routes;
pub mod serde_custom;
pub mod token;

use std::error;
use std::fmt;
use std::io;
use std::ops::Deref;
use std::str::FromStr;

use rocket::http::Status;
use rocket::response::{Response, Responder};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de;

/// Top level error enum
#[derive(Debug)]
pub enum Error {
    /// A generic/unknown error
    GenericError(String),
    /// Authentication error
    Auth(auth::Error),
    /// CORS error
    CORS(cors::Error),
    /// Token Error
    Token(token::Error),
    /// IO errors
    IOError(io::Error),
}

impl_from_error!(auth::Error, Error::Auth);
impl_from_error!(cors::Error, Error::CORS);
impl_from_error!(token::Error, Error::Token);
impl_from_error!(String, Error::GenericError);
impl_from_error!(io::Error, Error::IOError);

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Auth(ref e) => e.description(),
            Error::CORS(ref e) => e.description(),
            Error::Token(ref e) => e.description(),
            Error::IOError(ref e) => e.description(),
            Error::GenericError(ref e) => e,
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Auth(ref e) => Some(e as &error::Error),
            Error::CORS(ref e) => Some(e as &error::Error),
            Error::Token(ref e) => Some(e as &error::Error),
            Error::IOError(ref e) => Some(e as &error::Error),
            Error::GenericError(_) => Some(self as &error::Error),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Auth(ref e) => fmt::Display::fmt(e, f),
            Error::CORS(ref e) => fmt::Display::fmt(e, f),
            Error::Token(ref e) => fmt::Display::fmt(e, f),
            Error::IOError(ref e) => fmt::Display::fmt(e, f),
            Error::GenericError(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

impl<'r> Responder<'r> for Error {
    fn respond(self) -> Result<Response<'r>, Status> {
        match self {
            Error::Auth(e) => e.respond(),
            Error::CORS(e) => e.respond(),
            Error::Token(e) => e.respond(),
            e => {
                error_!("{}", e);
                Err(Status::InternalServerError)
            }
        }
    }
}

/// Wrapper around `hyper::Url` with `Serialize` and `Deserialize` implemented
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Url(hyper::Url);
impl_deref!(Url, hyper::Url);

impl FromStr for Url {
    type Err = hyper::error::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Url(hyper::Url::from_str(s)?))
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0.as_str())
    }
}

impl Serialize for Url {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl Deserialize for Url {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer
    {
        struct UrlVisitor;
        impl de::Visitor for UrlVisitor {
            type Value = Url;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid URL string")
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
                where E: de::Error
            {
                Ok(Url(hyper::Url::from_str(&value).map_err(|e| E::custom(format!("{}", e)))?))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                where E: de::Error
            {
                Ok(Url(hyper::Url::from_str(value).map_err(|e| E::custom(format!("{}", e)))?))
            }
        }

        deserializer.deserialize_string(UrlVisitor)
    }
}

/// Application configuration. Usually deserialized from JSON for use.
///
/// The type parameter `B` is the [`auth::AuthenticatorConfiguration`] and by its associated
/// type, the `Authenticator` that is going to be used for HTTP Basic Authentication.
#[derive(Serialize, Deserialize, Debug)]
pub struct Configuration<B: auth::AuthenticatorConfiguration<hyper::header::Basic>> {
    /// Token configuration. See the type documentation for deserialization examples
    pub token: token::Configuration,
    /// The configuration for the authenticator that will handle HTTP Basic Authentication.
    pub basic_authenticator: B,
}

impl<B: auth::AuthenticatorConfiguration<hyper::header::Basic>> Configuration<B> {
    /// Launches the Rocket server with the configuration. This function blocks and never returns.
    ///
    /// # Panics
    /// This function will panic, if during the making of the authenticator, something goes wrong.
    pub fn launch(self) {
        let token_getter_cors_options = routes::TokenGetterCorsOptions::new(&self.token);

        let basic_authenticator = self.basic_authenticator
                                    .make_authenticator()
                                    .unwrap_or_else(|e| panic!("Error making Basic Authenticator: {}", e));
        let basic_authenticator: Box<auth::BasicAuthenticator> = Box::new(basic_authenticator);

        rocket::ignite()
            .mount("/",
                routes![routes::token_getter, routes::token_getter_options])
            .manage(self.token)
            .manage(token_getter_cors_options)
            .manage(basic_authenticator)
            .launch();
    }
}

#[cfg(test)]
mod tests {
    use std::default::Default;
    use std::str::FromStr;

    use serde_test::{Token, assert_tokens};

    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct TestUrl {
        url: Url,
    }

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

    #[test]
    fn url_serialization_token_round_trip() {
        let test = TestUrl { url: not_err!(Url::from_str("https://www.example.com/")) };

        assert_tokens(&test,
                      &[Token::StructStart("TestUrl", 1),
                        Token::StructSep,
                        Token::Str("url"),
                        Token::Str("https://www.example.com/"),
                        Token::StructEnd]);
    }
}
