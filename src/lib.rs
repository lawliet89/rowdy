//! # rowdy
//!
//! `rowdy` is a JSON Web token based authentication server based off Docker Registry's
//! [authentication protocol](https://docs.docker.com/registry/spec/auth/).
//!
//! ## Features
//!
//! - `clippy`: Enable clippy lints during builds

#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]
#![cfg_attr(feature="clippy", plugin(clippy))]

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

#[cfg(test)]
extern crate serde_test;

#[macro_use]
mod macros;
#[cfg(test)]
#[macro_use]
mod test;
pub mod header;
pub mod cors;
pub mod serde_custom;
pub mod token;

use std::error;
use std::fmt;
use std::io;
use std::str::FromStr;
use std::time::Duration;
use std::ops::Deref;

use jwt::jws;
use rocket::http::Status;
use rocket::response::{Response, Responder};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de;

#[derive(Debug)]
pub enum Error {
    GenericError(String),
    CORS(cors::Error),
    Token(token::Error),
    IOError(io::Error),
}

impl_from_error!(cors::Error, Error::CORS);
impl_from_error!(token::Error, Error::Token);
impl_from_error!(String, Error::GenericError);
impl_from_error!(io::Error, Error::IOError);

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::CORS(ref e) => e.description(),
            Error::Token(ref e) => e.description(),
            Error::IOError(ref e) => e.description(),
            Error::GenericError(ref e) => e,
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
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

const DEFAULT_EXPIRY_DURATION: u64 = 86400;

/// Application configuration. Usually deserialized from JSON for use.
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
/// #[macro_use]
/// extern crate serde_derive;
/// extern crate serde_json;
///
/// use rowdy::Configuration;
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
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Configuration {
    /// The issuer of the token. Usually the URI of the authentication server.
    /// The issuer URI will also be used in the UUID generation of the tokens.
    pub issuer: String,
    /// Origins that are allowed to issue CORS request. This is needed for browser
    /// access to the authentication server, but tools like `curl` do not obey nor enforce the CORS convention.
    ///
    /// This enum (de)serialized as an [untagged](https://serde.rs/enum-representations.html) enum variant.
    ///
    /// See [`cors::AllowedOrigins`] for serialization examples.
    pub allowed_origins: cors::AllowedOrigins,
    /// The audience intended for your tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<jwt::SingleOrMultipleStrings>,
    /// Defaults to `none`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<jws::Algorithm>,
    /// Secrets for use in signing and encrypting a JWT.
    /// This enum (de)serialized as an [untagged](https://serde.rs/enum-representations.html) enum variant.
    /// Defaults to `None`.
    ///
    /// See [`token::Secret`] for serialization examples
    #[serde(default)]
    pub secret: token::Secret,
    /// Expiry duration of tokens, in seconds. Defaults to 24 hours when deserialized and left unfilled
    #[serde(with = "::serde_custom::duration", default = "Configuration::default_expiry_duration")]
    pub expiry_duration: Duration,
}

impl Configuration {
    fn default_expiry_duration() -> Duration {
        Duration::from_secs(DEFAULT_EXPIRY_DURATION)
    }
}

/// Launches the Rocket server with the configuration. This function blocks and never returns.
pub fn launch(config: Configuration) {
    let token_getter_options = token::TokenGetterCorsOptions::new(&config);
    rocket::ignite()
        .mount("/",
               routes![token::token_getter, token::token_getter_options])
        .manage(config)
        .manage(token_getter_options)
        .launch();
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
