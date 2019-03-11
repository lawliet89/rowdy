//! [![Build Status](https://travis-ci.org/lawliet89/rowdy.svg)](https://travis-ci.org/lawliet89/rowdy)
//! [![Dependency Status](https://dependencyci.com/github/lawliet89/rowdy/badge)](https://dependencyci.com/github/lawliet89/rowdy)
//! [![Crates.io](https://img.shields.io/crates/v/rowdy.svg)](https://crates.io/crates/rowdy)
//! [![Repository](https://img.shields.io/github/tag/lawliet89/rowdy.svg)](https://github.com/lawliet89/rowdy)
//! [![Documentation](https://docs.rs/rowdy/badge.svg)](https://docs.rs/rowdy)
//!
//! Documentation: [Stable](https://docs.rs/rowdy) | [Master](https://lawliet89.github.io/rowdy/)
//!
//! `rowdy` is a [Rocket](https://rocket.rs/)  based JSON Web token based authentication server
//! based off Docker Registry's
//! [authentication protocol](https://docs.docker.com/registry/spec/auth/).
//!
//! # Features
//!
//! - `simple_authenticator`: A simple CSV based authenticator
//! - `ldap_authenticator`: An LDAP based authenticator
//!
//! By default, the `simple_authenticator` feature is turned on.
//!
//! # `rowdy` Authentication Flow
//!
//! The authentication flow is inspired by
//! [Docker Registry](https://docs.docker.com/registry/spec/auth/) authentication specification.
//!
//! ## JSON Web Tokens
//!
//! Authentication makes use of two types of [JSON Web Tokens (JWT)](https://jwt.io/):
//! Access and Refresh tokens.
//!
//! ### Access Token
//!
//! The access token is a short lived JWT that allows users to access resources within the scope
//! that they are allowed to. The access token itself contains enough information for services
//! to verify the user and their permissions in a stateless manner.
//!
//! ### Refresh Token
//!
//! The refresh token allows users to retrieve a new access token without needing to
//! re-authenticate. As such, the refresh token is longer lived, but can be revoked.
//!
//! ## Authentication Flow
//!
//! 1. Client attempts to access a resource on a protected service.
//! 1. Service responds with a `401 Unauthorized` authentication challenge with information on
//!  how to authenticate
//! provided in the `WWW-Authenticate` response header.
//! 1. Using the information from the previous step, the client authenticates with the
//! authentication server. The client
//! will receive, among other information, opaque access and refresh tokens.
//! 1. The client retries the original request with the Bearer token embedded in the request’s
//! Authorization header.
//! 1. The service authorizes the client by validating the Bearer token and the claim set
//! embedded within it and
//! proceeds as usual.
//!
//! ### Authentication Challenge
//!
//! Services will challenge users who do not provide a valid token via the HTTP response
//! `401 Unauthorized`. Details for
//! authentication is provided in the `WWW-Authenticate` header.
//!
//! ```text
//! Www-Authenticate: Bearer realm="https://www.auth.com",service="https://www.example.com",scope="all"
//! ```
//!
//! The `realm` field indicates the authentcation server endpoint which clients should proceed to
//! authenticate against.
//!
//! The `service` field indicates the `service` value that clients should use when attempting to
//! authenticate at `realm`.
//!
//! The `scope` field indicates the `scope` value that clients should use when attempting to
//! authenticate at `realm`.
//!
//! ### Retrieving an Access Token (and optionally Refresh Token) from the Authentication Server
//!
//! A HTTP `GET` request should be made to the `realm` endpoint provided above. The endpoint will
//! support the following uery paremeters:
//!
//! - `service`: The service that the client is authenticating for. This should be the same as
//! the `service` value in the previous step
//! - `scope`: The scope that the client wishes to authenticate for.
//! This should be the same as the `scope` value in the previous step.
//! - `offline_token`: Set to `true` if a refresh token is also required. Defaults to `false`.
//! Cannot be set to `true` when using a refresh token to retrieve a new access token.
//!
//! When authenticating for the first time, clients should send the user's username and passwords
//! in the form of `Basic` authentication. If the client already has a prior refresh token and
//! would like to obtain a new access token, the client should send the refresh token in the form
//! of `Bearer` authentication.
//!
//! If successful, the authentcation server will return a `200 OK` response with a
//! JSON body containing the following fields:
//!
//! - `token`: An opaque Access (`Bearer`) token that clients should supply to subsequent requests
//! in the `Authorization` header.
//! - `expires_in`: The duration in seconds since the token was issued that it will remain valid.
//! - `issued_at`: RFC3339-serialized UTC standard time at which a given token was issued.
//! - `refresh_token`: An opaque `Refresh` token which can be used to get additional access
//! tokens for the same subject with different scopes. This token should be kept secure by
//! the client and only sent to the authorization server which issues access tokens.
//! This field will only be set when `offline_token=true` is provided in the request.
//!
//! If this fails, the server will return with the appropriate `4xx` response.
//!
//! ### Using the Access Token
//!
//! Once the client has a token, it will try the request again with the token placed in the
//! HTTP Authorization header like so:
//!
//! ```text
//! Authorization: Bearer <token>
//! ```
//!
//! ### Using the Refresh Token to Retrieve a New Access Token
//!
//! When the client's Access token expires, and it has previously asked for a Refresh Token,
//! the client can make a `GET` request to the same endpoint that the client used to retrieve the
//! access token (the `realm` URL in an authentication challenge).
//!
//! The steps are described in the section "Retrieving an Access Token" above. The process is the
//! same as the initial authentication except that instead of using `Basic` authentication,
//! the client should instead send the refresh token retrieved prior as `Bearer` authentication.
//! Also, `offline_token` cannot be requested for when requesting for a new access token using a
//! refresh token. (HTTP 401 will be returned if this happens.)
//!
//! ### Example
//!
//! This example uses `curl` to make request to the some (hypothetical) protected endpoint.
//! It requires [`jq`](https://stedolan.github.io/jq/) to parse JSON.
//!
//! ```bash
//! PROTECTED_RESOURCE="https://www.example.com/protected/resource/"
//!
//! # Save the response headers of our first request to the endpoint to get the Www-Authenticate
//! # header
//! RESPONSE_HEADER=$(tempfile);
//! curl --dump-header "${RESPONSE_HEADER}" "${PROTECTED_RESOURCE}"
//!
//! # Extract the realm, the service, and the scope from the Www-Authenticate header
//! WWWAUTH=$(cat "${RESPONSE_HEADER}" | grep "Www-Authenticate")
//! REALM=$(echo "${WWWAUTH}" | grep -o '\(realm\)="[^"]*"' | cut -d '"' -f 2)
//! SERVICE=$(echo "${WWWAUTH}" | grep -o '\(service\)="[^"]*"' | cut -d '"' -f 2)
//! SCOPE=$(echo "${WWWAUTH}" | grep -o '\(scope\)="[^"]*"' | cut -d '"' -f 2)
//!
//! # Build the URL to query the auth server
//! AUTH_URL="${REALM}?service=${SERVICE}&scope=${SCOPE}&offline_token=true"
//!
//! # Query the auth server to get a token -- replace the username and password
//! # below with the value from 1password
//! TOKEN=$(curl -s --user "mozart:password" "${AUTH_URL}")
//!
//! # Get the access token from the JSON string: {"token": "...."}
//! ACCESS_TOKEN=$(echo ${TOKEN} | jq .token | tr -d '"')
//!
//! # Query the resource again, but this time with a bearer token
//! curl -v -H "Authorization: Bearer ${ACCESS_TOKEN}" "${PROTECTED_RESOURCE}"
//!
//! # Get the refresh token
//! REFRESH_TOKEN=$(echo "${TOKEN}" | jq .refresh_token | tr -d '"')
//!
//! # Get a new access token
//! NEW_TOKEN=$(curl --header "Authorization: Bearer ${REFRESH_TOKEN}" "${AUTH_URL}")
//!
//! # Parse the new access token
//! NEW_ACCESS_TOKEN=$(echo "${TOKEN}" | jq .token | tr -d '"')
//!
//! # Query the resource again, but this time with a new access token
//! curl -v -H "Authorization: Bearer ${NEW_ACCESS_TOKEN}" "${PROTECTED_RESOURCE}"
//! ```
//!
//! ## Scope
//!
//! Not in use at the moment. Just use `all`.
//!
#![feature(proc_macro_hygiene, decl_macro)]
// See https://github.com/rust-unofficial/patterns/blob/master/anti_patterns/deny-warnings.md
#![allow(
    legacy_directory_ownership,
    missing_copy_implementations,
    missing_debug_implementations,
    unknown_lints,
    unsafe_code,
    intra_doc_link_resolution_failure
)]
#![deny(
    const_err,
    dead_code,
    deprecated,
    exceeding_bitshifts,
    improper_ctypes,
    missing_docs,
    mutable_transmutes,
    no_mangle_const_items,
    non_camel_case_types,
    non_shorthand_field_patterns,
    non_upper_case_globals,
    overflowing_literals,
    path_statements,
    plugin_as_library,
    stable_features,
    trivial_casts,
    trivial_numeric_casts,
    unconditional_recursion,
    unknown_crate_types,
    unreachable_code,
    unused_allocation,
    unused_assignments,
    unused_attributes,
    unused_comparisons,
    unused_extern_crates,
    unused_features,
    unused_imports,
    unused_import_braces,
    unused_qualifications,
    unused_must_use,
    unused_mut,
    unused_parens,
    unused_results,
    unused_unsafe,
    unused_variables,
    variant_size_differences,
    warnings,
    while_true
)]
#![doc(test(attr(allow(unused_variables), deny(warnings))))]

use biscuit as jwt;

use hyper;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate rocket;
// we are using the "log_!" macros which are redefined from `log`'s
use rocket_cors as cors;

#[macro_use]
extern crate serde_derive;
use serde_json;

#[cfg(test)]
extern crate serde_test;

#[macro_use]
mod macros;
#[cfg(test)]
#[macro_use]
mod test;
pub mod auth;
mod routes;
pub mod serde_custom;
pub mod token;

pub use self::routes::routes;

use std::error;
use std::fmt;
use std::io;
use std::ops::Deref;
use std::str::FromStr;

use ring::rand::SystemRandom;
use rocket::http::Status;
use rocket::response::{Responder, Response};
use rocket::Request;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use serde_json::Map as JsonMap;
pub use serde_json::Value as JsonValue;

/// Top level error enum
#[derive(Debug)]
pub enum Error {
    /// A generic/unknown error
    GenericError(String),
    /// A bad request resulting from bad request parameters/headers
    BadRequest(String),
    /// Authentication error
    Auth(auth::Error),
    /// CORS error
    CORS(cors::Error),
    /// Token Error
    Token(token::Error),
    /// IO errors
    IOError(io::Error),
    /// An error launcing Rocket
    LaunchError(rocket::error::LaunchError),

    /// Unsupported operation
    UnsupportedOperation,
}

impl_from_error!(auth::Error, Error::Auth);
impl_from_error!(cors::Error, Error::CORS);
impl_from_error!(token::Error, Error::Token);
impl_from_error!(String, Error::GenericError);
impl_from_error!(io::Error, Error::IOError);
impl_from_error!(rocket::error::LaunchError, Error::LaunchError);

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::UnsupportedOperation => "This operation is not supported",
            Error::Auth(ref e) => e.description(),
            Error::CORS(ref e) => e.description(),
            Error::Token(ref e) => e.description(),
            Error::IOError(ref e) => e.description(),
            Error::LaunchError(ref e) => e.description(),
            Error::GenericError(ref e) | Error::BadRequest(ref e) => e,
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Auth(ref e) => Some(e),
            Error::CORS(ref e) => Some(e),
            Error::Token(ref e) => Some(e),
            Error::IOError(ref e) => Some(e),
            Error::LaunchError(ref e) => Some(e),
            Error::UnsupportedOperation | Error::GenericError(_) | Error::BadRequest(_) => {
                Some(self)
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::UnsupportedOperation => write!(f, "{}", error::Error::description(self)),
            Error::Auth(ref e) => fmt::Display::fmt(e, f),
            Error::CORS(ref e) => fmt::Display::fmt(e, f),
            Error::Token(ref e) => fmt::Display::fmt(e, f),
            Error::IOError(ref e) => fmt::Display::fmt(e, f),
            Error::GenericError(ref e) => fmt::Display::fmt(e, f),
            Error::LaunchError(ref e) => fmt::Display::fmt(e, f),
            Error::BadRequest(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

impl<'r> Responder<'r> for Error {
    fn respond_to(self, request: &Request<'_>) -> Result<Response<'r>, Status> {
        match self {
            Error::Auth(e) => e.respond_to(request),
            Error::CORS(e) => e.respond_to(request),
            Error::Token(e) => e.respond_to(request),
            Error::BadRequest(e) => {
                error_!("{}", e);
                Err(Status::BadRequest)
            }
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.as_str())
    }
}

impl Serialize for Url {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for Url {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UrlVisitor;
        impl<'de> de::Visitor<'de> for UrlVisitor {
            type Value = Url;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a valid URL string")
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Url(
                    hyper::Url::from_str(&value).map_err(|e| E::custom(e.to_string()))?
                ))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Url(
                    hyper::Url::from_str(value).map_err(|e| E::custom(e.to_string()))?
                ))
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
///         "allowed_origins": { "Some": ["https://www.example.com", "https://www.foobar.com"] },
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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Configuration<B> {
    /// Token configuration. See the type documentation for deserialization examples
    pub token: token::Configuration,
    /// The configuration for the authenticator that will handle HTTP Basic Authentication.
    pub basic_authenticator: B,
}

impl<B: auth::AuthenticatorConfiguration<auth::Basic>> Configuration<B> {
    /// Ignites the rocket with various configuration objects, but does not mount any routes.
    /// Remember to mount routes and call `launch` on the returned Rocket object.
    /// See the struct documentation for an example.
    pub fn ignite(&self) -> Result<rocket::Rocket, Error> {
        let token_getter_cors_options = self.token.cors_option();

        let basic_authenticator = self.basic_authenticator.make_authenticator()?;
        let basic_authenticator: Box<auth::BasicAuthenticator> = Box::new(basic_authenticator);

        // Prepare the keys
        let keys = self.token.keys()?;

        Ok(rocket::ignite()
            .manage(self.token.clone())
            .manage(basic_authenticator)
            .manage(keys)
            .attach(token_getter_cors_options))
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
pub fn launch<B: auth::AuthenticatorConfiguration<auth::Basic>>(
    config: Configuration<B>,
) -> rocket::error::LaunchError {
    let rocket = config.ignite().unwrap_or_else(|e| panic!("{}", e));
    rocket.mount("/", routes()).launch()
}

/// Return a psuedo random number generator
pub(crate) fn rng() -> &'static SystemRandom {
    use std::ops::Deref;

    lazy_static! {
        static ref RANDOM: SystemRandom = SystemRandom::new();
    }

    RANDOM.deref()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde_test::{assert_tokens, Token};

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
        let test = TestUrl {
            url: not_err!(Url::from_str("https://www.example.com/")),
        };

        assert_tokens(
            &test,
            &[
                Token::Struct {
                    name: "TestUrl",
                    len: 1,
                },
                Token::Str("url"),
                Token::Str("https://www.example.com/"),
                Token::StructEnd,
            ],
        );
    }
}
