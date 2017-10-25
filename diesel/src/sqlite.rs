//! SQLite authenticator module
//!
//! Requires `features = ["sqlite"]` in your `Cargo.toml`
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use r2d2::Config;
use r2d2_diesel::ConnectionManager;

use rowdy;
use rowdy::auth::{AuthenticatorConfiguration, Basic};

use {ConnectionPool, Error, PooledConnection};
use schema;

/// A rowdy authenticator that uses a SQLite backed database to provide the users
pub type Authenticator = ::Authenticator<SqliteConnection>;

impl Authenticator {
    /// Connect to a SQLite database at a certain path
    ///
    /// Note: Diesel does not support [URI filenames](https://www.sqlite.org/c3ref/open.html)
    /// at this moment.
    ///
    /// # Warning about in memory databases
    ///
    /// Rowdy uses a connection pool to SQLite databases. So a distinct
    /// [`:memory:` database ](https://www.sqlite.org/inmemorydb.html) is created for ever
    /// connection in the pool. Since URI filenames are not supported,
    /// `file:memdb1?mode=memory&cache=shared` cannot be used.
    pub fn with_path<S: AsRef<str>>(path: S) -> Result<Self, Error> {
        // Attempt a test connection with diesel
        let _ = Self::connect(path.as_ref())?;

        let config = Config::default();
        let manager = ConnectionManager::new(path.as_ref());
        debug_!("Creating a connection pool");
        let pool = ConnectionPool::new(config, manager)?;
        Ok(Self::new(pool))
    }

    /// Test connection with the database uri
    fn connect(path: &str) -> Result<SqliteConnection, Error> {
        debug_!("Attempting a connection to SQLite database");
        Ok(SqliteConnection::establish(path)?)
    }
}

impl schema::Migration<SqliteConnection> for Authenticator {
    type Connection = PooledConnection<ConnectionManager<SqliteConnection>>;

    fn connection(&self) -> Result<Self::Connection, ::Error> {
        self.get_pooled_connection()
    }

    fn migration_query(&self) -> &str {
        r#"CREATE TABLE IF NOT EXISTS 'users' (
    'username' VARCHAR(255) UNIQUE NOT NULL,
    'hash' BLOB(32) NOT NULL,
    'salt' BLOB(255) NOT NULL,
    PRIMARY KEY ('username')
);"#
    }
}

/// (De)Serializable configuration for SQLite Authenticator. This struct should be included
/// in the base `Configuration`.
/// # Examples
/// ```json
/// {
///     "database": "file:/home/fred/data.db"
/// }
/// ```
#[derive(Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct Configuration {
    /// Connect to a SQLite database at a certain path
    ///
    /// Note: Diesel does not support [URI filenames](https://www.sqlite.org/c3ref/open.html)
    /// at this moment.
    ///
    /// # Warning about in memory databases
    ///
    /// Rowdy uses a connection pool to SQLite databases. So a distinct
    /// [`:memory:` database ](https://www.sqlite.org/inmemorydb.html) is created for ever
    /// connection in the pool. Since URI filenames are not supported,
    /// `file:memdb1?mode=memory&cache=shared` cannot be used.
    pub path: String,
}

impl AuthenticatorConfiguration<Basic> for Configuration {
    type Authenticator = Authenticator;

    fn make_authenticator(&self) -> Result<Self::Authenticator, rowdy::Error> {
        Ok(Authenticator::with_path(&self.path)?)
    }
}


#[cfg(test)]
mod tests {
    use std::sync::{Once, ONCE_INIT};

    use diesel::connection::SimpleConnection;
    use rowdy::auth::Authenticator;

    use schema::Migration;
    use super::*;

    static SEED: Once = ONCE_INIT;

    /// Reset and seed the databse. This should only be run once.
    fn migrate_and_seed(authenticator: &super::Authenticator) {
        SEED.call_once(|| {
            let query = format!(
                include_str!("../test/fixtures/sqlite.sql"),
                migration = authenticator.migration_query()
            );

            let connection = authenticator.get_pooled_connection().expect("to succeed");
            connection.batch_execute(&query).expect("to work");
        });
    }

    fn make_authenticator() -> super::Authenticator {
        let authenticator = super::Authenticator::with_path("../target/sqlite.db")
            .expect("To be constructed successfully");
        migrate_and_seed(&authenticator);
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
    fn sqlite_authenticator_configuration_deserialization() {
        use serde_json;
        use rowdy::auth::AuthenticatorConfiguration;

        let json = r#"{
            "path": "../target/test.db"
        }"#;

        let deserialized: Configuration =
            serde_json::from_str(json).expect("to deserialize successfully");
        let expected_config = Configuration {
            path: From::from("../target/test.db"),
        };
        assert_eq!(deserialized, expected_config);

        let _ = expected_config
            .make_authenticator()
            .expect("to be constructed correctly");
    }
}
