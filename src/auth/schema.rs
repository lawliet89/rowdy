#![allow(unused_qualifications)]
table! {
    users (username) {
        username -> Varchar,
        pw_hash -> Varchar,
        salt -> Varchar,
    }
}
