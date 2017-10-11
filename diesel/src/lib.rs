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

use serde_json::value;
use r2d2::PooledConnection;
use r2d2_diesel::ConnectionManager;
// FIXME: Remove dependency on `ring`.
use ring::constant_time::verify_slices_are_equal;
use rowdy::{JsonMap, JsonValue};
use rowdy::auth::{self, AuthenticationResult, Authorization, Basic};
use rowdy::auth::util::{hash_password_digest, hex_dump};


#[cfg(test)]
#[macro_use]
mod test;

pub mod schema;
pub mod mysql;

/// A connection pool for the Diesel backed authenticators
///
/// Type `T` should implement
/// [`Connection`](http://docs.diesel.rs/diesel/connection/trait.Connection.html)
pub type ConnectionPool<T> = r2d2::Pool<r2d2_diesel::ConnectionManager<T>>;

/// Errors from using `rowdy-diesel`.
///
/// This enum `impl From<Error> for rowdy::Error`, and can be used with the `?` operator
/// in places where `rowdy::Error` is expected.
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
            Error::ConnectionError(e) => {
                rowdy::Error::Auth(rowdy::auth::Error::GenericError((e.to_string())))
            }
            Error::DieselError(e) => {
                rowdy::Error::Auth(rowdy::auth::Error::GenericError((e.to_string())))
            }
            Error::ConnectionTimeout => rowdy::Error::Auth(rowdy::auth::Error::GenericError(
                "Timed out connecting to the database".to_string(),
            )),
            Error::InitializationError => rowdy::Error::Auth(rowdy::auth::Error::GenericError(
                "Error initializing a database connection pool".to_string(),
            )),
            Error::AuthenticationFailure => {
                rowdy::Error::Auth(rowdy::auth::Error::AuthenticationFailure)
            }
        }
    }
}

/// A user record in the database
#[derive(Queryable, Serialize, Deserialize)]
pub struct User {
    username: String,
    hash: Vec<u8>,
    salt: Vec<u8>,
}

/// A generic authenticator backed by a connection to a database via [diesel](http://diesel.rs/).
///
/// Instead of using this, you should use the "specialised" authenticators defined in the
/// `mysql`, `pg`, or `sqlite` modules for your database.
pub struct Authenticator<T>
where
    T: diesel::connection::Connection + 'static,
{
    pool: ConnectionPool<T>,
}

impl<T> Authenticator<T>
where
    T: diesel::connection::Connection + 'static,
    String: diesel::types::FromSql<diesel::types::Text, <T as diesel::Connection>::Backend>,
    Vec<u8>: diesel::types::FromSql<diesel::types::Binary, <T as diesel::Connection>::Backend>,
{
    /// Creates an authenticator backed by a table in a database using a connection pool.
    pub fn new(pool: ConnectionPool<T>) -> Self {
        Self { pool }
    }

    /// Retrieve a connection to the database from the pool
    pub(crate) fn get_pooled_connection(
        &self,
    ) -> Result<PooledConnection<ConnectionManager<T>>, Error> {
        debug_!("Retrieving a connection from the pool");
        Ok(self.pool.get()?)
    }

    /// Search for the specified user entry
    fn search(&self, connection: &T, search_user: &str) -> Result<Vec<User>, Error> {
        use diesel::FilterDsl;
        use diesel::ExpressionMethods;
        use diesel::LoadDsl;
        use schema::users::dsl::*;

        debug_!("Querying user {} from database", search_user);
        let results = users
            .filter(username.eq(search_user))
            .load::<User>(connection)?;
        Ok(results)
    }

    /// Hash a password with the salt. See struct level documentation for the algorithm used.
    // TODO: Write an "example" tool to salt easily
    pub fn hash_password(password: &str, salt: &[u8]) -> Result<String, Error> {
        Ok(hex_dump(hash_password_digest(password, salt).as_ref()))
    }

    /// Serialize a user as payload for a refresh token
    fn serialize_refresh_token_payload(user: &User) -> Result<JsonValue, Error> {
        let user = value::to_value(user).map_err(|_| Error::AuthenticationFailure)?;
        let mut map = JsonMap::with_capacity(1);
        let _ = map.insert("user".to_string(), user);
        Ok(JsonValue::Object(map))
    }

    /// Deserialize a user from a refresh token payload
    fn deserialize_refresh_token_payload(refresh_payload: JsonValue) -> Result<User, Error> {
        match refresh_payload {
            JsonValue::Object(ref map) => {
                let user = map.get("user").ok_or_else(|| Error::AuthenticationFailure)?;
                // TODO verify the user object matches the database
                Ok(value::from_value(user.clone())
                    .map_err(|_| Error::AuthenticationFailure)?)
            }
            _ => Err(Error::AuthenticationFailure),
        }
    }

    /// Build an `AuthenticationResult` for a `User`
    fn build_authentication_result(
        user: &User,
        include_refresh_payload: bool,
    ) -> Result<AuthenticationResult, Error> {
        let refresh_payload = if include_refresh_payload {
            Some(Self::serialize_refresh_token_payload(user)?)
        } else {
            None
        };

        // TODO implement private claims in DB
        let private_claims = JsonValue::Object(JsonMap::new());

        Ok(AuthenticationResult {
            subject: user.username.clone(),
            private_claims,
            refresh_payload,
        })
    }

    /// Verify that some user with the provided password exists in the database, and the password
    /// is correct.
    ///
    /// Returns the payload to be included in a refresh token if successful
    pub fn verify(
        &self,
        username: &str,
        password: &str,
        include_refresh_payload: bool,
    ) -> Result<AuthenticationResult, Error> {
        let user = {
            let connection = self.get_pooled_connection()?;
            let mut user = self.search(&connection, username)
                .map_err(|_e| Error::AuthenticationFailure)?;
            if user.len() != 1 {
                Err(Error::AuthenticationFailure)?;
            }

            user.pop().unwrap() // safe to unwrap
        };
        assert_eq!(username, user.username);

        let actual_password_digest = hash_password_digest(password, &user.salt);
        if !verify_slices_are_equal(actual_password_digest.as_ref(), &user.hash).is_ok() {
            Err(Error::AuthenticationFailure)
        } else {
            Self::build_authentication_result(&user, include_refresh_payload)
        }
    }
}

impl<T> auth::Authenticator<Basic> for Authenticator<T>
where
    T: diesel::connection::Connection + 'static,
    String: diesel::types::FromSql<diesel::types::Text, <T as diesel::Connection>::Backend>,
    Vec<u8>: diesel::types::FromSql<diesel::types::Binary, <T as diesel::Connection>::Backend>,
{
    fn authenticate(
        &self,
        authorization: &Authorization<Basic>,
        include_refresh_payload: bool,
    ) -> Result<AuthenticationResult, rowdy::Error> {
        let username = authorization.username();
        let password = authorization.password().unwrap_or_else(|| "".to_string());
        Ok(self.verify(&username, &password, include_refresh_payload)?)
    }

    fn authenticate_refresh_token(
        &self,
        refresh_payload: &JsonValue,
    ) -> Result<AuthenticationResult, rowdy::Error> {
        let user = Self::deserialize_refresh_token_payload(refresh_payload.clone())?;
        Ok(Self::build_authentication_result(&user, false)?)
    }
}
