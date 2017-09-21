//! Diesel Support for Rowdy
//!
//! Allows you to use a Database table as the authentication soruce for Rowdy
//!
//! TODO: Document How Argon2i is used: 32 bytes hash, 32 bytes salt

#[macro_use]
extern crate diesel;
#[macro_use]
extern crate diesel_codegen;
#[macro_use]
extern crate log;
extern crate ring;
#[macro_use]
extern crate rocket;
extern crate rowdy;
// we are using the "log_!" macros which are redefined from `log`'s
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

#[cfg(test)]
#[macro_use]
mod test;

pub mod schema;
pub mod mysql;

#[derive(Debug)]
pub enum Error {
    /// A diesel connection error
    ConnectionError(diesel::result::ConnectionError),
    /// A generic error occuring from Diesel
    DieselError(diesel::result::Error),
    /// Authentication error
    AuthenticationFailure,
}

impl From<diesel::result::ConnectionError> for Error {
    fn from(error: diesel::result::ConnectionError) -> Error {
        Error::ConnectionError(error)
    }
}

impl From<diesel::result::Error> for Error {
    fn from(error: diesel::result::Error) -> Error {
        Error::DieselError(error)
    }
}

impl From<Error> for rowdy::Error {
    fn from(error: Error) -> rowdy::Error {
        match error {
            Error::ConnectionError(e) => rowdy::Error::Auth(rowdy::auth::Error::GenericError((e.to_string()))),
            Error::DieselError(e) => rowdy::Error::Auth(rowdy::auth::Error::GenericError((e.to_string()))),
            Error::AuthenticationFailure => rowdy::Error::Auth(rowdy::auth::Error::AuthenticationFailure),
        }
    }
}
