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
extern crate r2d2;
extern crate r2d2_diesel;
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

/// A connection pool for the Diesel backed authenticators
///
/// Type `T` should implement
/// [`diesel::connection::Connection`](http://docs.diesel.rs/diesel/connection/trait.Connection.html)
pub type ConnectionPool<T> = r2d2::Pool<r2d2_diesel::ConnectionManager<T>>;

#[derive(Debug)]
pub enum Error {
    /// A diesel connection error
    ConnectionError(diesel::result::ConnectionError),
    /// A generic error occuring from Diesel
    DieselError(diesel::result::Error),
    /// Error while attempting to initialize a connection pool
    InitializationError,
    /// Timeout while attempting to retrieve a connection from the connection pool
    ConnectionTimeout,
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

impl From<r2d2::InitializationError> for Error {
    fn from(_: r2d2::InitializationError) -> Error {
        Error::InitializationError
    }
}

impl From<r2d2::GetTimeout> for Error {
    fn from(_: r2d2::GetTimeout) -> Error {
        Error::ConnectionTimeout
    }
}

impl From<Error> for rowdy::Error {
    fn from(error: Error) -> rowdy::Error {
        match error {
            Error::ConnectionError(e) => rowdy::Error::Auth(rowdy::auth::Error::GenericError((e.to_string()))),
            Error::DieselError(e) => rowdy::Error::Auth(rowdy::auth::Error::GenericError((e.to_string()))),
            Error::ConnectionTimeout => rowdy::Error::Auth(rowdy::auth::Error::GenericError(
                "Timed out connecting to the database".to_string(),
            )),
            Error::InitializationError => rowdy::Error::Auth(rowdy::auth::Error::GenericError(
                "Error initializing a database connection pool".to_string(),
            )),
            Error::AuthenticationFailure => rowdy::Error::Auth(rowdy::auth::Error::AuthenticationFailure),
        }
    }
}
