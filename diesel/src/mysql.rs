//! MySql authenticator module
use diesel::prelude::*;
use diesel::mysql::MysqlConnection;
use r2d2::Config;
use r2d2_diesel::ConnectionManager;

use rowdy;
use rowdy::auth::{AuthenticatorConfiguration, Basic};

use {ConnectionPool, Error};

/// A rowdy authenticator that uses a MySQL backed database to provide the users
pub type Authenticator = ::Authenticator<MysqlConnection>;

impl Authenticator {
    /// Using a database connection string of the form `mysql://[user[:password]@]host/database_name`,
    /// create an authenticator that is backed by a connection pool to a MySQL database
    pub fn with_uri(uri: &str) -> Result<Self, Error> {
        // Attempt a test connection with diesel
        let _ = Self::connect(uri)?;

        let config = Config::default();
        let manager = ConnectionManager::new(uri);
        debug_!("Creating a connection pool");
        let pool = ConnectionPool::new(config, manager)?;
        Ok(Self::new(pool))
    }

    /// Create a new `Authenticator` with a database config
    ///
    pub fn with_configuration(host: &str, port: u16, database: &str, user: &str, pass: &str) -> Result<Self, Error> {
        let database_uri = format!("mysql://{}:{}@{}:{}/{}", user, pass, host, port, database);
        Self::with_uri(&database_uri)
    }

    /// Test connection with the database uri
    fn connect(uri: &str) -> Result<MysqlConnection, Error> {
        debug_!("Attempting a connection to MySQL database");
        Ok(MysqlConnection::establish(uri)?)
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
    use rowdy::auth::util::hex_dump;
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

        let result = not_err!(authenticator.authenticate_refresh_token(result.refresh_payload.as_ref().unwrap(),));
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
