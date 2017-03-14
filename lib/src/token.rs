use std::error;
use std::fmt;
use std::io::Cursor;
use std::time::Duration;

use chrono::{DateTime, UTC};
use jwt::{self, jws};
use rocket::http::{ContentType, Status};
use rocket::response::{Response, Responder};
use serde::{Serialize, Deserialize};
use serde_json;

#[derive(Debug)]
pub enum Error {
    /// Raised when attempting to encode an already encoded token
    TokenAlreadyEncoded,
    /// Raised when attempting to decode an already decoded token
    TokenAlreadyDecoded,
    /// Raised when attempting to use a decoded token in a response
    TokenNotEncoded,

    /// Errors during token encoding/decoding
    JWTError(jwt::errors::Error),
    /// Errors during token serialization
    TokenSerializationError(serde_json::Error),
}

impl_from_error!(jwt::errors::Error, Error::JWTError);
impl_from_error!(serde_json::Error, Error::TokenSerializationError);

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::TokenAlreadyEncoded => "Token is already encoded",
            Error::TokenAlreadyDecoded => "Token is already decoded",
            Error::TokenNotEncoded => "Token is not encoded and cannot be used in a response",
            Error::JWTError(ref e) => e.description(),
            Error::TokenSerializationError(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::JWTError(ref e) => Some(e as &error::Error),
            Error::TokenSerializationError(ref e) => Some(e as &error::Error),
            _ => Some(self as &error::Error),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::JWTError(ref e) => fmt::Display::fmt(e, f),
            Error::TokenSerializationError(ref e) => fmt::Display::fmt(e, f),
            _ => write!(f, "{}", error::Error::description(self)),
        }
    }
}

impl<'r> Responder<'r> for Error {
    fn respond(self) -> Result<Response<'r>, Status> {
        error_!("Token Error: {:?}", self);
        Err(Status::InternalServerError)
    }
}

#[derive(Default, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct PrivateClaim {}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Token<T: Serialize + Deserialize> {
    pub token: jwt::JWT<T>,
    #[serde(with = "::serde_custom::duration")]
    pub expires_in: Duration,
    pub issued_at: DateTime<UTC>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>, // TODO
}

impl<T: Serialize + Deserialize> Token<T> {
    pub fn new(header: jws::Header, claims_set: jwt::ClaimsSet<T>, expires_in: &Duration) -> Self {
        Token {
            token: jwt::JWT::new_decoded(header, claims_set),
            expires_in: expires_in.clone(),
            issued_at: UTC::now(),
            refresh_token: None,
        }
    }

    /// Consumes self and encode the embedded JWT with signature.
    /// If the JWT is already encoded, this returns an error
    pub fn encode(mut self, secret: jws::Secret) -> Result<Self, Error> {
        match self.token {
            jwt::JWT::Encoded(_) => Err(Error::TokenAlreadyEncoded),
            jwt @ jwt::JWT::Decoded { .. } => {
                self.token = jwt.into_encoded(secret)?;
                Ok(self)
            }
        }
    }

    /// Consumes self and decode the embedded JWT with signature verification
    /// If the JWT is already decoded, this returns an error
    pub fn decode(mut self, secret: jws::Secret, algorithm: jws::Algorithm) -> Result<Self, Error> {
        match self.token {
            jwt @ jwt::JWT::Encoded(_) => {
                self.token = jwt.into_decoded(secret, algorithm)?;
                Ok(self)
            }
            jwt::JWT::Decoded { .. } => Err(Error::TokenAlreadyDecoded),
        }
    }

    fn serialize_and_respond(self) -> Result<String, Error> {
        if let jwt::JWT::Decoded { .. } = self.token {
            Err(Error::TokenNotEncoded)?
        }
        let serialized = serde_json::to_string(&self)?;
        Ok(serialized)
    }
}

impl<'r, T: Serialize + Deserialize> Responder<'r> for Token<T> {
    fn respond(self) -> Result<Response<'r>, Status> {
        match self.serialize_and_respond() {
            Ok(serialized) => Response::build().header(ContentType::JSON).sized_body(Cursor::new(serialized)).ok(),
            Err(e) => Err::<String, Error>(e).respond(),
        }
    }
}

/// Secrets for use in signing and encrypting a JWT.
/// This enum (de)serialized as an [untagged](https://serde.rs/enum-representations.html) enum variant.
/// Defaults to `None`.
///
/// # Serialization Examples
/// ## No secret
/// ```json
/// {
///     "secret": null
/// }
/// ```
/// ## HMAC secret string
/// ```json
/// {
///     "secret": "some_secret_string"
/// }
/// ```
/// ## RSA Key pair
/// ```json
/// {
///     "secret": { "rsa_private": "private.der", "rsa_public": "public.der" }
/// }
/// ```
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Secret {
    /// No secret -- used when no signature or encryption is required.
    None,
    /// Secret for HMAC signing
    String(String),
    /// DER RSA Key pair.
    /// See [`jwt::jws::Secret`] for more details.
    RSAKeyPair {
        /// Path to DER encoded private key
        rsa_private: String,
        /// Path to DER encoded public key
        rsa_public: String,
    },
}

impl Default for Secret {
    fn default() -> Self {
        Secret::None
    }
}

impl Secret {
    /// Create a [`jws::Secret`] for the purpose of signing
    pub fn for_signing(&self) -> Result<jws::Secret, Error> {
        match *self {
            Secret::None => Ok(jws::Secret::None),
            Secret::String(ref secret) => Ok(jws::Secret::bytes_from_str(secret)),
            Secret::RSAKeyPair { ref rsa_private, .. } => Ok(jws::Secret::rsa_keypair_from_file(rsa_private)?),
        }
    }

    /// Create a [`jws::Secret`] for the purpose of verifying signatures
    pub fn for_verification(&self) -> Result<jws::Secret, Error> {
        match *self {
            Secret::None => Ok(jws::Secret::None),
            Secret::String(ref secret) => Ok(jws::Secret::bytes_from_str(secret)),
            Secret::RSAKeyPair { ref rsa_public, .. } => Ok(jws::Secret::public_key_from_file(rsa_public)?),
        }
    }
}
