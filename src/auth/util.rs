//! Utility functions to aid in managing users
//!
//! Primarily, this module provides a useful function to hash a password, in combination with a
//! salt to produce a hash with [Argon2i](https://en.wikipedia.org/wiki/Argon2).
//!
//! The hash produced will be 32 bytes long.
use argon2rs;
use jwt::jwa::{self, SecureRandom};

static CHARS: &'static [u8] = b"0123456789abcdef";

/// Given a password and a salt, generate an argon2i hash 32 bytes in length
///
/// Note that a salt between 8 and 2^32-1 bytes must be provided.
pub fn hash_password_digest(password: &str, salt: &[u8]) -> Vec<u8> {
    let bytes = password.as_bytes();
    let mut out = vec![0; argon2rs::defaults::LENGTH]; // 32 bytes
    let argon2 = argon2rs::Argon2::default(argon2rs::Variant::Argon2i);
    argon2.hash(&mut out, bytes, salt, &[], &[]);
    out
}

/// Generate a new random salt based on the configured salt length
///
/// For argon2i, you should use a salt between 8 and 2^32-1 bytes
///
/// If this function fails, no extra details can be provided.
/// See [`Unspecified`](https://briansmith.org/rustdoc/ring/error/struct.Unspecified.html)
pub fn generate_salt(salt_length: usize) -> Result<Vec<u8>, ()> {
    let mut salt: Vec<u8> = vec![0; salt_length];
    jwa::rng().fill(&mut salt).map_err(|_| ())?;
    Ok(salt)
}

/// Dump a bunch of bytes as a hexadecimal string
pub fn hex_dump(bytes: &[u8]) -> String {
    let mut v = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes.iter() {
        v.push(CHARS[(byte >> 4) as usize]);
        v.push(CHARS[(byte & 0xf) as usize]);
    }

    unsafe { String::from_utf8_unchecked(v) }
}
