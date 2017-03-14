#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]

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

macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl From<$f> for Error {
            fn from(f: $f) -> Error { $e(f) }
        }
    }
}

#[cfg(test)]
#[macro_use]
mod test;
pub mod cors;
pub mod serde_custom;
pub mod token;

use std::default::Default;
use std::error;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;
use std::ops::Deref;

use rocket::http::Status;
use rocket::http::Method::*;
use rocket::State;
use rocket::response::{Response, Responder};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use serde::de;

/// Implement a simple Deref from `From` to `To` where `From` is a newtype struct containing `To`
macro_rules! impl_deref {
    ($f:ty, $t:ty) => {
        impl Deref for $f {
            type Target = $t;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    CORS(cors::Error),
    Token(token::Error),
}

impl_from_error!(cors::Error, Error::CORS);
impl_from_error!(token::Error, Error::Token);

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::CORS(_) => "CORS Error",
            Error::Token(_) => "Token error",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::CORS(ref e) => Some(e as &error::Error),
            Error::Token(ref e) => Some(e as &error::Error),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CORS(ref e) => fmt::Display::fmt(e, f),
            Error::Token(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

impl<'r> Responder<'r> for Error {
    fn respond(self) -> Result<Response<'r>, Status> {
        match self {
            Error::CORS(e) => e.respond(),
            Error::Token(e) => e.respond(),
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

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Configuration {
    pub allowed_origins: cors::AllowedOrigins,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<jwt::jws::Algorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<token::Secret>,
    /// Expiry duration of tokens, in seconds
    #[serde(with = "::serde_custom::duration", default = "Configuration::default_expiry_duration")]
    pub expiry_duration: Duration,
}

impl Configuration {
    fn default_expiry_duration() -> Duration {
        Duration::from_secs(86400)
    }
}

struct HelloCorsOptions(cors::Options);
impl_deref!(HelloCorsOptions, cors::Options);

const HELLO_METHODS: &[rocket::http::Method] = &[Get];
const HELLO_HEADERS: &'static [&'static str] = &["Authorization"];

impl HelloCorsOptions {
    fn new(config: &Configuration) -> Self {
        HelloCorsOptions(cors::Options {
                             allowed_origins: config.allowed_origins.clone(),
                             allowed_methods: HELLO_METHODS.iter().cloned().collect(),
                             allowed_headers: HELLO_HEADERS.iter().map(|s| s.to_string().into()).collect(),
                             allow_credentials: true,
                             ..Default::default()
                         })
    }
}

#[derive(FromForm)]
struct AuthParam {
    service: String,
    scope: String,
    offline_token: Option<bool>,
}

#[options("/?<_auth_param>")]
fn hello_options(origin: cors::Origin,
                 method: cors::AccessControlRequestMethod,
                 headers: cors::AccessControlRequestHeaders,
                 options: State<HelloCorsOptions>,
                 _auth_param: AuthParam)
                 -> Result<cors::Response<()>, cors::Error> {
    options.preflight(&origin, &method, Some(&headers))
}

#[get("/?<auth_param>")]
fn hello(origin: cors::Origin,
         auth_param: AuthParam,
         options: State<HelloCorsOptions>)
         -> Result<cors::Response<token::Token<token::PrivateClaim>>, Error> {
    let token = token::Token::<token::PrivateClaim> {
        token: jwt::JWT::new_decoded(jwt::jws::Header::default(), jwt::ClaimsSet::<token::PrivateClaim> {
            private: Default::default(),
            registered: Default::default(),
        }),
        expires_in: Duration::from_secs(86400),
        issued_at: chrono::UTC::now(),
        refresh_token: None,
    };
    let token = token.encode(jwt::jws::Secret::Bytes("secret".to_string().into_bytes()))?;
    Ok(options.respond(token, &origin)?)
}

pub fn launch(config: Configuration) {
    let hello_options = HelloCorsOptions::new(&config);
    rocket::ignite().mount("/", routes![hello, hello_options]).manage(hello_options).launch();
}
