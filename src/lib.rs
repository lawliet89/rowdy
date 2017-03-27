//! # rowdy
//!
//! `rowdy` is a JSON Web token based authentication server based off Docker Registry's
//! [authentication protocol](https://docs.docker.com/registry/spec/auth/).
//!
//! ## Features
//!
//! - `clippy_lints`: Enable clippy lints during builds
//! - `simple_authenticator`: A simple CSV based authenticator
//! - `ldap_authenticator`: An LDAP based authenticator
//!
//! By default, the `simple_authenticator` feature is turned on.

#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]
#![cfg_attr(feature="clippy_lints", plugin(clippy))]

#![warn(missing_docs)]
#![doc(test(attr(allow(unused_variables), deny(warnings))))]

extern crate biscuit as jwt;
extern crate chrono;
extern crate hyper;
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
#[cfg(feature = "ldap_authenticator")]
extern crate openldap;
#[cfg(feature = "ldap_authenticator")]
extern crate strfmt;

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

pub use self::routes::routes;

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

/// A sequence of bytes, either as an array of unsigned 8 bit integers, or a string which will be
/// treated as UTF-8.
/// This enum is (de)serialized [`untagged`](https://serde.rs/enum-representations.html).
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum ByteSequence {
    /// A string which will be converted to UTF-8 and then to bytes.
    String(String),
    /// A sequence of unsigned 8 bits integers which will be treated as bytes.
    Bytes(Vec<u8>),
}

impl ByteSequence {
    /// Returns the byte sequence.
    pub fn as_bytes(&self) -> Vec<u8> {
        match *self {
            ByteSequence::String(ref string) => string.to_string().into_bytes(),
            ByteSequence::Bytes(ref bytes) => bytes.to_vec(),
        }
    }
}

/// Application configuration. Usually deserialized from JSON for use.
///
/// The type parameter `B` is the [`auth::AuthenticatorConfiguration`] and by its associated
/// type, the `Authenticator` that is going to be used for HTTP Basic Authentication.
///
/// # Examples
/// ```
/// extern crate rowdy;
/// extern crate serde_json;
///
/// use rowdy::Configuration;
/// use rowdy::auth::NoOpConfiguration;
///
/// # fn main() {
/// // We are using the `NoOp` authenticator
/// let json = r#"{
///     "token" : {
///         "issuer": "https://www.acme.com",
///         "allowed_origins": ["https://www.example.com", "https://www.foobar.com"],
///         "audience": ["https://www.example.com", "https://www.foobar.com"],
///         "signature_algorithm": "RS256",
///         "secret": {
///                     "rsa_private": "test/fixtures/rsa_private_key.der",
///                     "rsa_public": "test/fixtures/rsa_public_key.der"
///                    },
///         "expiry_duration": 86400
///        },
///        "basic_authenticator": {}
/// }"#;
/// let config: Configuration<NoOpConfiguration> = serde_json::from_str(json).unwrap();
/// let rocket = config.ignite().unwrap().mount("/", rowdy::routes());
/// // then `rocket.launch()`!
/// # }
/// ```
#[derive(Serialize, Deserialize, Debug)]
pub struct Configuration<B: auth::AuthenticatorConfiguration<auth::Basic>> {
    /// Token configuration. See the type documentation for deserialization examples
    pub token: token::Configuration,
    /// The configuration for the authenticator that will handle HTTP Basic Authentication.
    pub basic_authenticator: B,
}

impl<B: auth::AuthenticatorConfiguration<auth::Basic>> Configuration<B> {
    /// Ignites the rocket with various configuration objects, but does not mount any routes.
    /// Remember to mount routes and call `launch` on the returned Rocket object.
    /// See the struct documentation for an example.
    pub fn ignite(self) -> Result<rocket::Rocket, Error> {
        let token_getter_cors_options = routes::TokenGetterCorsOptions::new(&self.token);

        let basic_authenticator = self.basic_authenticator.make_authenticator()?;
        let basic_authenticator: Box<auth::BasicAuthenticator> = Box::new(basic_authenticator);

        Ok(rocket::ignite().manage(self.token).manage(token_getter_cors_options).manage(basic_authenticator))
    }
}

/// Convenience function to ignite and launch rowdy. This function will never return
///
/// # Panics
/// Panics if during the Rocket igition, something goes wrong.
///
/// # Example
/// ```rust,no_run
/// extern crate rowdy;
/// extern crate serde_json;
///
/// use rowdy::Configuration;
/// use rowdy::auth::NoOpConfiguration;
///
/// # fn main() {
/// // We are using the `NoOp` authenticator
/// let json = r#"{
///     "token" : {
///         "issuer": "https://www.acme.com",
///         "allowed_origins": ["https://www.example.com", "https://www.foobar.com"],
///         "audience": ["https://www.example.com", "https://www.foobar.com"],
///         "signature_algorithm": "RS256",
///         "secret": {
///                     "rsa_private": "test/fixtures/rsa_private_key.der",
///                     "rsa_public": "test/fixtures/rsa_public_key.der"
///                    },
///         "expiry_duration": 86400
///        },
///        "basic_authenticator": {}
/// }"#;
/// let config: Configuration<NoOpConfiguration> = serde_json::from_str(json).unwrap();
///
/// rowdy::launch(config);
/// # }
/// ```
pub fn launch<B: auth::AuthenticatorConfiguration<auth::Basic>>(config: Configuration<B>) {
    let rocket = config.ignite().unwrap_or_else(|e| panic!("{}", e));
    rocket.mount("/", routes::routes()).launch()
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
