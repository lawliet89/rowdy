//! Schema of the `users` table that will be used with Rowdy
//! If you have more sophisticated needs, you are able to add more columns to the basic
//! columns needed for rowdy to work.
//!
//! The schema required for the table as expressed using Diesel's
//! [`table!`](http://docs.diesel.rs/diesel/macro.table.html) macro is
//!
//! ```rust,ignore
//! table! {
//!     users (username) {
//!         username -> Varchar,
//!         hash -> Binary,
//!         salt -> Varbinary,
//!     }
//! }
//! ```
//!
//! In standard SQL parlance, this is equivalent to
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS `users` (
//!     `username` VARCHAR(255) UNIQUE NOT NULL,
//!     `hash` BINARY(32) NOT NULL,
//!     `salt` VARBINARY(255) NOT NULL,
//!     PRIMARY KEY (`username`)
//! );
//! ```

/// Diesel table definition inside a module to allow for some lints
mod table_macro {
    #![allow(unused_qualifications, unused_import_braces)]
    table! {
        /// Table used to hold users and their hashed passwords
        ///
        /// Hashing is done with the `argon2i` algorithm with a salt.
        users (username) {
            /// Username for the user. Also the primary key
            username -> Varchar,
            /// A argon2i hash of the user's password
            hash -> Binary,
            /// Salt used to generate the password hash
            salt -> Varbinary,
        }
    }
}
// Then we re-export those to public for use.
pub use self::table_macro::*;

use std::ops::Deref;

use Connection;

/// Trait to provide idempotent minimal migration to create the table necessary for `rowdy-diesel`
/// to work. If you have more sophisticated needs, you are able to add more columns to the basic
/// columns needed for rowdy to work.
// TODO: Look into folding this into the base `Authenticator` struct once const generics
// is implemented. See https://github.com/rust-lang/rust/issues/44580
pub trait Migration<T>
where
    T: Connection + 'static,
{
    /// Connection type for the migration to work with
    type Connection: Deref<Target = T>;

    /// Provide a connection for the migration to work with
    // TODO: Object safety?
    fn connection(&self) -> Result<Self::Connection, ::Error>;

    /// Format the migration query based on the connection type
    fn migration_query(&self) -> &str;

    /// Provide idempotent minimal migration to create the table necessary for `rowdy-diesel`
    /// to work
    fn migrate(&self) -> Result<(), ::Error> {
        let query = self.migration_query();

        let connection = self.connection()?;
        connection.batch_execute(&query)?;
        Ok(())
    }
}
