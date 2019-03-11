//! MySQL authenticator module
//!
//! Requires `features = ["mysql"]` in your `Cargo.toml`
use diesel::mysql::MysqlConnection;
use diesel::prelude::*;
use diesel::r2d2::{Builder, ConnectionManager};

use rowdy;
use rowdy::auth::{AuthenticatorConfiguration, Basic};

use schema;
use {Error, PooledConnection};

/// A rowdy authenticator that uses a MySQL backed database to provide the users
pub type Authenticator = ::Authenticator<MysqlConnection>;

impl Authenticator {
    /// Using a database connection string of the form
    /// `mysql://[user[:password]@]host/database_name`,
    /// create an authenticator that is backed by a connection pool to a MySQL database
    pub fn with_uri(uri: &str) -> Result<Self, Error> {
        // Attempt a test connection with diesel
        let _ = Self::connect(uri)?;

        debug_!("Creating a connection pool");
        let manager = ConnectionManager::new(uri.as_ref());
        let pool = Builder::new().build(manager)?;
        Ok(Self::new(pool))
    }

    /// Create a new `Authenticator` with a database config
    ///
    pub fn with_configuration(
        host: &str,
        port: u16,
        database: &str,
        user: &str,
        pass: &str,
    ) -> Result<Self, Error> {
        let database_uri = format!("mysql://{}:{}@{}:{}/{}", user, pass, host, port, database);
        Self::with_uri(&database_uri)
    }

    /// Test connection with the database uri
    fn connect(uri: &str) -> Result<MysqlConnection, Error> {
        debug_!("Attempting a connection to MySQL database");
        Ok(MysqlConnection::establish(uri)?)
    }
}

impl schema::Migration<MysqlConnection> for Authenticator {
    type Connection = PooledConnection<ConnectionManager<MysqlConnection>>;

    fn connection(&self) -> Result<Self::Connection, ::Error> {
        self.get_pooled_connection()
    }

    fn migration_query(&self) -> &str {
        r#"CREATE TABLE IF NOT EXISTS `users` (
    `username` VARCHAR(255) UNIQUE NOT NULL,
    `hash` BINARY(32) NOT NULL,
    `salt` VARBINARY(255) NOT NULL,
    PRIMARY KEY (`username`)
);"#
    }
}

/// (De)Serializable configuration for MySQL Authenticator. This struct should be included
/// in the base `Configuration`.
/// # Examples
/// ```json
/// {
///     "host": "localhost",
///     "port": 3306,
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
    use std::sync::{Once, ONCE_INIT};

    use diesel::connection::SimpleConnection;
    use rowdy::auth::Authenticator;

    use super::*;
    use schema::Migration;

    static SEED: Once = ONCE_INIT;

    /// Reset and seed the databse. This should only be run once.
    fn reset_and_seed(authenticator: &super::Authenticator) {
        SEED.call_once(|| {
            let query = format!(
                include_str!("../test/fixtures/mysql.sql"),
                migration = authenticator.migration_query()
            );

            let connection = authenticator.get_pooled_connection().expect("to succeed");
            connection.batch_execute(&query).expect("to work");
        });
    }

    fn make_authenticator() -> super::Authenticator {
        let authenticator =
            super::Authenticator::with_configuration("127.0.0.1", 3306, "rowdy", "root", "")
                .expect("To be constructed successfully");
        reset_and_seed(&authenticator);
        authenticator
    }

    #[test]
    fn hashing_is_done_correctly() {
        let hashed_password = super::Authenticator::hash_password("password", &[0; 32])
            .expect("to hash successfully");
        assert_eq!(
            "e6e1111452a5574d8d64f6f4ba6fabc86af5c45c341df1eb23026373c41d24b8",
            hashed_password
        );
    }

    #[test]
    fn hashing_is_done_correctly_for_unicode() {
        let hashed_password = super::Authenticator::hash_password("冻住，不许走!", &[0; 32])
            .expect("to hash successfully");
        assert_eq!(
            "b400a5eea452afcc67a81602f28012e5634404ddf1e043d6ff1df67022c88cd2",
            hashed_password
        );
    }

    /// Migration should be idempotent
    #[test]
    fn migration_is_idempotent() {
        let authenticator = make_authenticator();
        authenticator
            .migrate()
            .expect("To succeed and be idempotent")
    }

    #[test]
    fn authentication_with_username_and_password() {
        let authenticator = make_authenticator();

        let _ = authenticator
            .verify("foobar", "password", false)
            .expect("To verify correctly");

        let result = authenticator
            .verify("mei", "冻住，不许走!", false)
            .expect("to be verified");

        // refresh refresh_payload is not provided when not requested
        assert!(result.refresh_payload.is_none());
    }

    #[test]
    fn authentication_with_refresh_payload() {
        let authenticator = make_authenticator();

        let result = authenticator
            .verify("foobar", "password", true)
            .expect("To verify correctly");
        // refresh refresh_payload is provided when requested
        assert!(result.refresh_payload.is_some());

        let result = authenticator
            .authenticate_refresh_token(result.refresh_payload.as_ref().unwrap())
            .expect("to be successful");
        assert!(result.refresh_payload.is_none());
    }

    #[test]
    fn mysql_authenticator_configuration_deserialization() {
        use rowdy::auth::AuthenticatorConfiguration;
        use serde_json;

        let json = r#"{
            "host": "127.0.0.1",
            "port": 3306,
            "database": "rowdy",
            "user": "root",
            "password": ""
        }"#;

        let deserialized: Configuration =
            serde_json::from_str(json).expect("to deserialize successfully");
        let expected_config = Configuration {
            host: "127.0.0.1".to_string(),
            port: 3306,
            database: "rowdy".to_string(),
            user: "root".to_string(),
            password: "".to_string(),
        };
        assert_eq!(deserialized, expected_config);

        let _ = expected_config
            .make_authenticator()
            .expect("to be constructed correctly");
    }
}
