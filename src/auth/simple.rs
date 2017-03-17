//! Simple authenticator module
use std::io::Read;
use std::collections::HashMap;

use csv;
use hyper::header::Basic;
use ring::{digest, test};
use ring::constant_time::verify_slices_are_equal;

use super::Error;

// Code for conversion to hex stolen from rustc-serialize:
// https://doc.rust-lang.org/rustc-serialize/src/rustc_serialize/hex.rs.html

type Users = HashMap<String, Vec<u8>>;

/// A simple authenticator that uses a CSV backed user database.
///
/// Requires the `simple_authenticator` feature, which is enabled by default.
///
/// The user database should be a CSV file, or a "CSV-like" file
/// (meaning you can choose to use some other character as field delimiter instead of comma)
/// where the first column is the username, and the second column
/// is a hashed password.
///
/// # Password Hashing
/// See `SimpleAuthenticator::hash_password` for the implementation of password hashing.
/// The password is hashed from a _UTF-8 encoded password string_ `password` and the bytes of a
/// salt `salt`, by concatenating the bytes in the order `password` then `salt` and then taking a SHA256 digest
/// of the concatenated bytes. The bytes are then represented as Hexadecimal and stored.
///
/// If your password is `password`, and the salt is `salty`, you can use `openssl` to generate the digest:
///
/// ```sh
/// echo -n 'passwordsalty' | openssl dgst -sha256
/// ```
pub struct SimpleAuthenticator {
    users: Users,
    salt: Vec<u8>,
}

static CHARS: &'static [u8] = b"0123456789abcdef";

impl SimpleAuthenticator {
    /// Create a new `SimpleAuthenticator` with the provided salt and a CSV Reader.
    ///
    /// # Examples
    /// ```
    /// extern crate csv;
    /// extern crate rowdy;
    ///
    /// use rowdy::auth::SimpleAuthenticator;
    /// # fn main() {
    /// let csv = "foobar,29d6afd14bbcdf0b43d1f2c4fd8ecbe8bdedd5ee255e5fa530a3fb968cbbfa1a
    /// mei,e3cd32c1bafe41ba0d6998d5ea8623f453cf91244fd2cce6ab6ed90eacb0bd38";
    /// let csv_reader = csv::Reader::from_string(csv).has_headers(false);
    /// let authenticator = SimpleAuthenticator::new(b"salty", csv_reader).unwrap();
    /// # }
    /// ```
    pub fn new<R: Read>(salt: &[u8], csv: csv::Reader<R>) -> Result<Self, Error> {

        Ok(SimpleAuthenticator {
               salt: salt.to_vec(),
               users: Self::users_from_csv(csv)?,
           })
    }

    /// Create a new `SimpleAuthenticator` with the provided salt and a path to a CSV file.
    ///
    /// # Examples
    /// ```
    /// use rowdy::auth::SimpleAuthenticator;
    ///
    /// let authenticator = SimpleAuthenticator::with_csv_file(b"salty", "test/fixtures/users.csv", false, ',' as u8);
    /// ```
    pub fn with_csv_file(salt: &[u8], path: &str, has_headers: bool, delimiter: u8) -> Result<Self, Error> {
        let reader = csv::Reader::from_file(path)
            .map_err(|e| format!("{}", e))?
            .has_headers(has_headers)
            .delimiter(delimiter);
        Self::new(salt, reader)
    }

    fn users_from_csv<R: Read>(mut csv: csv::Reader<R>) -> Result<Users, Error> {
        let records: Vec<csv::Result<(String, String)>> = csv.decode().collect();

        if let Some(error) = records.iter().find(|record| record.is_err()) {
            error.as_ref().map_err(|e| format!("{}", e))?;
        }

        let users: HashMap<String, Result<Vec<u8>, String>> = records.iter()
            .map(|r| {
                     let &(ref username, ref hash) = r.as_ref().unwrap(); // safe to unwrap
                     (username.to_string(), test::from_hex(hash))
                 })
            .collect();


        if let Some((_, error)) = users.iter().find(|&(_, hash)| hash.is_err()) {
            error.as_ref().map_err(|e| e.to_string())?;
        }

        Ok(users.into_iter().map(|(u, h)| (u, h.unwrap())).collect())
    }

    /// Hash a password with the salt. See struct level documentation for the algorithm used.
    // TODO: Write an "example" tool to salt easily
    pub fn hash_password(&self, password: &str) -> String {
        Self::hex_dump(self.hash_password_digest(password).as_ref())
    }

    /// Verify that some user with the provided password exists in the CSV database, and the password is correct
    pub fn verify(&self, user: &str, password: &str) -> Result<(), Error> {
        match self.users.get(user) {
            None => Err(Error::AuthenticationFailure),
            Some(user) => {
                let actual_password_digest = self.hash_password_digest(password);
                if !verify_slices_are_equal(actual_password_digest.as_ref(), &*user).is_ok() {
                    Err(Error::AuthenticationFailure)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn hash_password_digest(&self, password: &str) -> digest::Digest {
        let mut bytes: Vec<u8> = password.as_bytes().to_vec();
        bytes.append(&mut self.salt.clone());

        digest::digest(&digest::SHA256, bytes.as_slice())
    }

    fn hex_dump(bytes: &[u8]) -> String {
        let mut v = Vec::with_capacity(bytes.len() * 2);
        for &byte in bytes.iter() {
            v.push(CHARS[(byte >> 4) as usize]);
            v.push(CHARS[(byte & 0xf) as usize]);
        }

        unsafe { String::from_utf8_unchecked(v) }
    }
}

impl super::Authenticator<Basic> for SimpleAuthenticator {
    fn authenticate(&self, authorization: &super::Authorization<Basic>) -> Result<(), Error> {
        let username = authorization.username();
        let password = authorization.password().unwrap_or_else(|| "".to_string());
        self.verify(&username, &password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_authenticator() -> SimpleAuthenticator {
        not_err!(SimpleAuthenticator::with_csv_file(b"salty", "test/fixtures/users.csv", false, ',' as u8))
    }

    #[test]
    fn test_hex_dump() {
        assert_eq!(SimpleAuthenticator::hex_dump("foobar".as_bytes()),
                   "666f6f626172");
    }

    #[test]
    fn test_hex_dump_all_bytes() {
        for i in 0..256 {
            assert_eq!(SimpleAuthenticator::hex_dump(&[i as u8]),
                       format!("{:02x}", i));
        }
    }

    #[test]
    fn hashing_is_done_correctly() {
        let authenticator = make_authenticator();
        let hashed_password = authenticator.hash_password("password");
        assert_eq!("29d6afd14bbcdf0b43d1f2c4fd8ecbe8bdedd5ee255e5fa530a3fb968cbbfa1a",
                   hashed_password);
    }

    #[test]
    fn hashing_is_done_correctly_for_unicode() {
        let authenticator = make_authenticator();
        let hashed_password = authenticator.hash_password("冻住，不许走!");
        assert_eq!("e3cd32c1bafe41ba0d6998d5ea8623f453cf91244fd2cce6ab6ed90eacb0bd38",
                   hashed_password);
    }

    #[test]
    fn smoke_test() {
        let authenticator = make_authenticator();
        let expected_keys = vec!["foobar".to_string(), "mei".to_string()];
        let mut actual_keys: Vec<String> = authenticator.users
            .keys()
            .cloned()
            .collect();
        actual_keys.sort();
        assert_eq!(expected_keys, actual_keys);

        not_err!(authenticator.verify("foobar", "password"));
        not_err!(authenticator.verify("mei", "冻住，不许走!"));
    }
}
