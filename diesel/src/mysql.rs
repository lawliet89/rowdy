//! MySql authenticator module
use diesel::prelude::*;
use diesel::mysql::MysqlConnection;

use serde_json::value;

// FIXME: Remove dependency on `ring`.
use ring::constant_time::verify_slices_are_equal;

use rowdy::{self, JsonMap, JsonValue};
use rowdy::auth::{self, Authorization, AuthenticatorConfiguration, AuthenticationResult, Basic};
use rowdy::auth::util::{hash_password_digest, hex_dump};

use Error;

/// MySql user record
#[derive(Queryable, Serialize, Deserialize)]
pub struct User {
    username: String,
    pw_hash: Vec<u8>,
    salt: Vec<u8>,
}

/// A simple authenticator that uses a MySql backed user database.
///
/// Requires the `mysql_authenticator` feature
///
/// The user database should be a MySql database with a table of the following format:
/// username(VARCHAR(255)), pw_hash(VARCHAR(255)), salt(VARCHAR(255))
///
/// # Password Hashing
/// See `Authenticator::hash_password` for the implementation of password hashing.
/// The password is hashed using the [`argon2i`](https://github.com/p-h-c/phc-winner-argon2) algorithm with
/// a randomly generated salt.
pub struct Authenticator {
    database_uri: String,
}

impl Authenticator {
    /// Create a new `Authenticator` with a database connection
    ///
    pub fn new(uri: String) -> Self {
        Authenticator { database_uri: uri }
    }

    /// Create a new `Authenticator` with a database config
    ///
    pub fn with_configuration(host: &str, port: u16, database: &str, user: &str, pass: &str) -> Result<Self, Error> {
        let database_uri: String = String::from(format!(
            "mysql://{}:{}@{}:{}/{}",
            user,
            pass,
            host,
            port,
            database
        ));
        let authenticator = Authenticator { database_uri };
        authenticator.test_connection().map(|()| authenticator)
    }

    fn test_connection(&self) -> Result<(), Error> {
        let _ = self.connect()?;
        Ok(())
    }

    /// Connects to MySql Server
    fn connect(&self) -> Result<MysqlConnection, Error> {
        debug_!("Connecting to MySQL server");
        let connection = MysqlConnection::establish(&self.database_uri)?;
        Ok(connection)
    }

    /// Search for the specified user entry
    fn search(&self, connection: &MysqlConnection, search_user: &str) -> Result<Vec<User>, Error> {
        use super::schema::users::dsl::*;
        let results = users.filter(username.eq(search_user)).load::<User>(
            connection,
        )?;
        Ok(results)
    }

    /// Hash a password with the salt. See struct level documentation for the algorithm used.
    // TODO: Write an "example" tool to salt easily
    pub fn hash_password(password: &str, salt: &[u8]) -> Result<String, Error> {
        Ok(hex_dump(hash_password_digest(password, salt).as_ref()))
    }

    /// Serialize a user as payload for a refresh token
    fn serialize_refresh_token_payload(user: &User) -> Result<JsonValue, Error> {
        let user = value::to_value(user).map_err(
            |_| Error::AuthenticationFailure,
        )?;
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
                Ok(value::from_value(user.clone()).map_err(|_| {
                    Error::AuthenticationFailure
                })?)
            }
            _ => Err(Error::AuthenticationFailure),
        }
    }

    /// Build an `AuthenticationResult` for a `User`
    fn build_authentication_result(user: &User, include_refresh_payload: bool) -> Result<AuthenticationResult, Error> {
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

    /// Verify that some user with the provided password exists in the database, and the password is correct.
    /// Returns the payload to be included in a refresh token if successful
    pub fn verify(
        &self,
        username: &str,
        password: &str,
        include_refresh_payload: bool,
    ) -> Result<AuthenticationResult, Error> {
        let user = {
            let connection = self.connect()?;
            let mut user = self.search(&connection, username).map_err(|_e| {
                Error::AuthenticationFailure
            })?;
            if user.len() != 1 {
                Err(Error::AuthenticationFailure)?;
            }

            user.pop().unwrap() // safe to unwrap
        };
        assert_eq!(username, user.username);

        let actual_password_digest = hash_password_digest(password, &user.salt);
        if !verify_slices_are_equal(actual_password_digest.as_ref(), &user.pw_hash).is_ok() {
            Err(Error::AuthenticationFailure)
        } else {
            Self::build_authentication_result(&user, include_refresh_payload)
        }
    }
}

impl auth::Authenticator<Basic> for Authenticator {
    fn authenticate(
        &self,
        authorization: &Authorization<Basic>,
        include_refresh_payload: bool,
    ) -> Result<AuthenticationResult, rowdy::Error> {
        let username = authorization.username();
        let password = authorization.password().unwrap_or_else(|| "".to_string());
        Ok(self.verify(&username, &password, include_refresh_payload)?)
    }

    fn authenticate_refresh_token(&self, refresh_payload: &JsonValue) -> Result<AuthenticationResult, rowdy::Error> {
        let user = Self::deserialize_refresh_token_payload(refresh_payload.clone())?;
        Ok(Self::build_authentication_result(&user, false)?)
    }
}

/// (De)Serializable configuration for `Authenticator`. This struct should be included
/// in the base `Configuration`.
/// # Examples
/// ```json
/// {
///     "host": "localhost",
///     "port": "3306",  // default if not specified
///     "database": "auth_users",
///     "user": "auth_user",
///     "password": "password"
/// }
/// ```
#[derive(Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct Configuration {
    /// Host for the MySql database manager - domain name or IP
    pub host: String,
    /// MySql database port - default 3306
    #[serde(default = "default_port")]
    pub port: u16,
    /// MySql database
    pub database: String,
    /// MySql user
    pub user: String,
    /// MySql password
    pub password: String,
}

fn default_port() -> u16 {
    3306
}

impl AuthenticatorConfiguration<Basic> for Configuration {
    type Authenticator = Authenticator;

    fn make_authenticator(&self) -> Result<Self::Authenticator, rowdy::Error> {
        Ok(Authenticator::with_configuration(
            &self.host,
            self.port,
            &self.database,
            &self.user,
            &self.password,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use rowdy::auth::Authenticator;
    use super::*;

    fn make_authenticator() -> super::Authenticator {
        not_err!(super::Authenticator::with_configuration(
            "127.0.0.1",
            3306,
            "rowdy",
            "root",
            "",
        ))
    }

    #[test]
    fn test_hex_dump() {
        assert_eq!(hex_dump(b"foobar"), "666f6f626172");
    }

    #[test]
    fn test_hex_dump_all_bytes() {
        for i in 0..256 {
            assert_eq!(hex_dump(&[i as u8]), format!("{:02x}", i));
        }
    }

    #[test]
    fn hashing_is_done_correctly() {
        let hashed_password = not_err!(super::Authenticator::hash_password("password", &[0; 32]));
        assert_eq!(
            "e6e1111452a5574d8d64f6f4ba6fabc86af5c45c341df1eb23026373c41d24b8",
            hashed_password
        );
    }

    #[test]
    fn hashing_is_done_correctly_for_unicode() {
        let hashed_password = not_err!(super::Authenticator::hash_password(
            "冻住，不许走!",
            &[0; 32],
        ));
        assert_eq!(
            "b400a5eea452afcc67a81602f28012e5634404ddf1e043d6ff1df67022c88cd2",
            hashed_password
        );
    }

    #[test]
    fn authentication_with_username_and_password() {
        let authenticator = make_authenticator();

        let _ = not_err!(authenticator.verify("foobar", "password", false));

        let result = not_err!(authenticator.verify("mei", "冻住，不许走!", false));
        assert!(result.refresh_payload.is_none()); // refresh refresh_payload is not provided when not requested
    }

    #[test]
    fn authentication_with_refresh_payload() {
        let authenticator = make_authenticator();

        let result = not_err!(authenticator.verify("foobar", "password", true));
        assert!(result.refresh_payload.is_some()); // refresh refresh_payload is provided when requested

        let result = not_err!(authenticator.authenticate_refresh_token(
            result.refresh_payload.as_ref().unwrap(),
        ));
        assert!(result.refresh_payload.is_none());
    }

    #[test]
    fn mysql_authenticator_configuration_deserialization() {
        use serde_json;
        use rowdy::auth::AuthenticatorConfiguration;

        let json = r#"{
            "host": "127.0.0.1",
            "port": 3306,
            "database": "rowdy",
            "user": "root",
            "password": ""
        }"#;

        let deserialized: Configuration = not_err!(serde_json::from_str(json));
        let expected_config = Configuration {
            host: "127.0.0.1".to_string(),
            port: 3306,
            database: "rowdy".to_string(),
            user: "root".to_string(),
            password: "".to_string(),
        };
        assert_eq!(deserialized, expected_config);

        let _ = not_err!(expected_config.make_authenticator());
    }
}
