//! Simple authenticator module
use std::io::{Read, Write};
use std::collections::HashMap;

use argon2rs;
use csv;
use jwt::jwa::{self, SecureRandom};
// FIXME: Remove dependency on `ring`.
use ring::test;
use ring::constant_time::verify_slices_are_equal;

use {Error, JsonValue, JsonMap};
use super::{Basic, AuthenticationResult};

// Code for conversion to hex stolen from rustc-serialize:
// https://doc.rust-lang.org/rustc-serialize/src/rustc_serialize/hex.rs.html

/// Typedef for the internal representation of a users database. The keys are the usernames, and the values
/// are a tuple of the password hash and salt.
pub type Users = HashMap<String, (Vec<u8>, Vec<u8>)>;

/// A simple authenticator that uses a CSV backed user database. _DO NOT USE THIS IN PRODUCTION_
///
/// Requires the `simple_authenticator` feature, which is enabled by default.
///
/// The user database should be a CSV file, or a "CSV-like" file
/// (meaning you can choose to use some other character as field delimiter instead of comma)
/// where the first column is the username, the second column is a hashed password, and the third column is the salt.
///
/// # Password Hashing
/// See `SimpleAuthenticator::hash_password` for the implementation of password hashing.
/// The password is hashed using the [`argon2i`](https://github.com/p-h-c/phc-winner-argon2) algorithm with
/// a randomly generated salt.
pub struct SimpleAuthenticator {
    users: Users,
}

static CHARS: &'static [u8] = b"0123456789abcdef";

impl SimpleAuthenticator {
    /// Create a new `SimpleAuthenticator` with the provided a CSV Reader.
    ///
    pub fn new<R: Read>(csv: csv::Reader<R>) -> Result<Self, Error> {
        warn_!("Do not use the Simple authenticator in production");
        Ok(SimpleAuthenticator { users: Self::users_from_csv(csv)? })
    }

    /// Create a new `SimpleAuthenticator` with a path to a CSV file.
    ///
    pub fn with_csv_file(path: &str, has_headers: bool, delimiter: u8) -> Result<Self, Error> {
        let reader = csv::Reader::from_file(path)
            .map_err(|e| e.to_string())?
            .has_headers(has_headers)
            .delimiter(delimiter);
        Self::new(reader)
    }

    fn users_from_csv<R: Read>(mut csv: csv::Reader<R>) -> Result<Users, Error> {
        // Parse the records, and look for errors
        let records: Vec<csv::Result<(String, String, String)>> = csv.decode().collect();
        let (records, errors): (Vec<_>, Vec<_>) = records.into_iter().partition(Result::is_ok);
        if !errors.is_empty() {
            let errors: Vec<String> = errors
                .into_iter()
                .map(|r| r.unwrap_err().to_string())
                .collect();
            Err(errors.join("; "))?;
        }

        type ParsedRecordBytes = Vec<Result<(String, Vec<u8>, Vec<u8>), String>>;
        // Decode the hex values from users
        let (users, errors): (ParsedRecordBytes, ParsedRecordBytes) = records
            .into_iter()
            .map(|r| {
                     let (username, hash, salt) = r.unwrap(); // safe to unwrap
                     let hash = test::from_hex(&hash)?;
                     let salt = test::from_hex(&salt)?;
                     Ok((username, hash, salt))
                 })
            .partition(Result::is_ok);

        if !errors.is_empty() {
            let errors: Vec<String> = errors.into_iter().map(|r| r.unwrap_err()).collect();
            Err(errors.join("; "))?;
        }

        let users: Users = users
            .into_iter()
            .map(|r| {
                     let (username, hash, salt) = r.unwrap(); // safe to unwrap
                     (username, (hash, salt))
                 })
            .collect();

        Ok(users)
    }

    /// Hash a password with the salt. See struct level documentation for the algorithm used.
    // TODO: Write an "example" tool to salt easily
    pub fn hash_password(password: &str, salt: &[u8]) -> Result<String, Error> {
        Ok(hex_dump(Self::hash_password_digest(password, salt)?.as_ref()))
    }

    /// Verify that some user with the provided password exists in the CSV database, and the password is correct.
    /// Returns the payload to be included in a refresh token if successful
    pub fn verify(&self,
                  username: &str,
                  password: &str,
                  include_refresh_payload: bool)
                  -> Result<AuthenticationResult, Error> {
        match self.users.get(username) {
            None => Err(Error::Auth(super::Error::AuthenticationFailure)),
            Some(&(ref hash, ref salt)) => {
                let actual_password_digest = Self::hash_password_digest(password, salt)?;
                if !verify_slices_are_equal(actual_password_digest.as_ref(), &*hash).is_ok() {
                    Err(Error::Auth(super::Error::AuthenticationFailure))
                } else {
                    let refresh_payload = if include_refresh_payload {
                        let mut map = JsonMap::with_capacity(2);
                        map.insert("user".to_string(), From::from(username));
                        map.insert("password".to_string(), From::from(password));
                        Some(JsonValue::Object(map))
                    } else {
                        None
                    };

                    Ok(AuthenticationResult {
                           subject: username.to_string(),
                           refresh_payload: refresh_payload,
                       })
                }
            }
        }
    }

    fn hash_password_digest(password: &str, salt: &[u8]) -> Result<Vec<u8>, Error> {
        let bytes = password.as_bytes();
        let mut out = vec![0; argon2rs::defaults::LENGTH];
        let argon2 = argon2rs::Argon2::default(argon2rs::Variant::Argon2i);
        argon2.hash(&mut out, bytes, salt, &[], &[]);
        Ok(out)
    }
}

impl super::Authenticator<Basic> for SimpleAuthenticator {
    fn authenticate(&self,
                    authorization: &super::Authorization<Basic>,
                    include_refresh_payload: bool)
                    -> Result<AuthenticationResult, Error> {
        warn_!("Do not use the Simple authenticator in production");
        let username = authorization.username();
        let password = authorization.password().unwrap_or_else(|| "".to_string());
        self.verify(&username, &password, include_refresh_payload)
    }

    fn authenticate_refresh_token(&self, refresh_payload: &JsonValue) -> Result<AuthenticationResult, ::Error> {
        warn_!("Do not use the Simple authenticator in production");
        match *refresh_payload {
            JsonValue::Object(ref map) => {
                let user = map.get("user")
                    .ok_or_else(|| super::Error::AuthenticationFailure)?
                    .as_str()
                    .ok_or_else(|| super::Error::AuthenticationFailure)?;
                let password = map.get("password")
                    .ok_or_else(|| super::Error::AuthenticationFailure)?
                    .as_str()
                    .ok_or_else(|| super::Error::AuthenticationFailure)?;
                self.verify(user, password, false)
            }
            _ => Err(super::Error::AuthenticationFailure)?,
        }
    }
}

/// (De)Serializable configuration for `SimpleAuthenticator`. This struct should be included
/// in the base `Configuration`.
/// # Examples
/// ```json
/// {
///     "csv_path": "test/fixtures/users.csv",
///     "has_headers": false,
///     "delimiter": " "
/// }
/// ```
#[derive(Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct SimpleAuthenticatorConfiguration {
    /// Path to the CSV database, in the format described by `SimpleAuthenticator`. This should be
    /// relative to the working directory, or an absolute path
    pub csv_path: String,
    /// Whether the CSV file has a header row or not. Defaults to `false`.
    #[serde(default)]
    pub has_headers: bool,
    /// The delimiter char. By default, this is ','.
    /// Because of the limitation of the `CSV` crate which elects to only allow delimiters with one byte,
    /// the `char` will be truncated to only one byte. This means you should only use delimiters that
    /// are ASCII.
    #[serde(default = "default_delimiter")]
    pub delimiter: char,
}

fn default_delimiter() -> char {
    ','
}

impl super::AuthenticatorConfiguration<Basic> for SimpleAuthenticatorConfiguration {
    type Authenticator = SimpleAuthenticator;

    fn make_authenticator(&self) -> Result<Self::Authenticator, ::Error> {
        Ok(SimpleAuthenticator::with_csv_file(&self.csv_path, self.has_headers, self.delimiter as u8)?)
    }
}

/// Convenience function to hash passwords from some users and provided passwords
/// The salt length must be between 8 and 2^32 - 1 bytes.
pub fn hash_passwords(users: &HashMap<String, String>, salt_len: usize) -> Result<Users, Error> {
    let mut hashed: Users = HashMap::new();
    for (user, password) in users {
        let salt = generate_salt(salt_len)?;
        let hash = SimpleAuthenticator::hash_password_digest(password, &salt)?;
        hashed.insert(user.to_string(), (hash, salt));
    }
    Ok(hashed)
}

/// Generate a new random salt based on the configured salt length
pub fn generate_salt(salt_length: usize) -> Result<Vec<u8>, Error> {
    let mut salt: Vec<u8> = vec![0; salt_length];
    jwa::rng().fill(&mut salt).map_err(|e| e.to_string())?;
    Ok(salt)
}

/// Convenience function to write `Users` to a Writer
pub fn write_csv<W: Write>(users: &Users, mut writer: W) -> Result<(), Error> {
    for (username, &(ref hash, ref salt)) in users {
        let record = vec![username.to_string(), hex_dump(hash), hex_dump(salt)].join(",");
        writer.write_all(record.as_bytes())?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn hex_dump(bytes: &[u8]) -> String {
    let mut v = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes.iter() {
        v.push(CHARS[(byte >> 4) as usize]);
        v.push(CHARS[(byte & 0xf) as usize]);
    }

    unsafe { String::from_utf8_unchecked(v) }
}

#[cfg(test)]
mod tests {
    use auth::Authenticator;
    use super::*;

    fn make_authenticator() -> SimpleAuthenticator {
        not_err!(SimpleAuthenticator::with_csv_file("test/fixtures/users.csv", false, b','))
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
        let hashed_password = not_err!(SimpleAuthenticator::hash_password("password", &[0; 32]));
        assert_eq!("e6e1111452a5574d8d64f6f4ba6fabc86af5c45c341df1eb23026373c41d24b8",
                   hashed_password);
    }

    #[test]
    fn hashing_is_done_correctly_for_unicode() {
        let hashed_password = not_err!(SimpleAuthenticator::hash_password("冻住，不许走!", &[0; 32]));
        assert_eq!("b400a5eea452afcc67a81602f28012e5634404ddf1e043d6ff1df67022c88cd2",
                   hashed_password);
    }

    #[test]
    fn csv_generation_round_trip() {
        use std::io::Cursor;

        let users: HashMap<String, String> = [("foobar", "password"), ("mei", "冻住，不许走!")]
            .into_iter()
            .map(|&(u, p)| (u.to_string(), p.to_string()))
            .collect();
        let users = not_err!(hash_passwords(&users, 32));

        let mut cursor: Cursor<Vec<u8>> = Cursor::new(vec![]);
        not_err!(write_csv(&users, &mut cursor));

        cursor.set_position(0);
        let authenticator = not_err!(SimpleAuthenticator::new(csv::Reader::from_reader(&mut cursor)
                                                                  .has_headers(false)));

        let expected_keys = vec!["foobar".to_string(), "mei".to_string()];
        let mut actual_keys: Vec<String> = authenticator.users.keys().cloned().collect();
        actual_keys.sort();
        assert_eq!(expected_keys, actual_keys);

        not_err!(authenticator.verify("foobar", "password", false));

        let result = not_err!(authenticator.verify("mei", "冻住，不许走!", false));
        assert!(result.refresh_payload.is_none()); // refresh refresh_payload is not provided when not requested
    }

    #[test]
    fn authentication_with_username_and_password() {
        let authenticator = make_authenticator();
        let expected_keys = vec!["foobar".to_string(), "mei".to_string()];
        let mut actual_keys: Vec<String> = authenticator.users.keys().cloned().collect();
        actual_keys.sort();
        assert_eq!(expected_keys, actual_keys);

        not_err!(authenticator.verify("foobar", "password", false));

        let result = not_err!(authenticator.verify("mei", "冻住，不许走!", false));
        assert!(result.refresh_payload.is_none()); // refresh refresh_payload is not provided when not requested
    }

    #[test]
    fn authentication_with_refresh_payload() {
        let authenticator = make_authenticator();

        let result = not_err!(authenticator.verify("foobar", "password", true));
        assert!(result.refresh_payload.is_some()); // refresh refresh_payload is provided when requested

        let result = not_err!(authenticator.authenticate_refresh_token(result.refresh_payload.as_ref().unwrap()));
        assert!(result.refresh_payload.is_none());
    }

    #[test]
    fn simple_authenticator_configuration_deserialization() {
        use serde_json;
        use auth::AuthenticatorConfiguration;

        let json = r#"{
            "csv_path": "test/fixtures/users.csv",
            "delimiter": ","
        }"#;

        let deserialized: SimpleAuthenticatorConfiguration = not_err!(serde_json::from_str(json));
        let expected_config = SimpleAuthenticatorConfiguration {
            csv_path: "test/fixtures/users.csv".to_string(),
            has_headers: false,
            delimiter: ',',
        };
        assert_eq!(deserialized, expected_config);

        not_err!(expected_config.make_authenticator());
    }
}
