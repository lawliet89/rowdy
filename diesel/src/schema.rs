//! Schema of the Users table that will be used with Rowdy

table! {
    users (username) {
        username -> Varchar,
        hash -> Binary,
        salt -> Varbinary,
    }
}
