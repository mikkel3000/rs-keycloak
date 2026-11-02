//! Password hashing primitives; callers must bound concurrency and keep secrets
//! out of logs and error messages.

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

/// An operation failed without including password or stored hash material.
#[derive(Debug)]
pub struct PasswordError;

/// Hashes a password using Argon2id and an independently generated OS salt.
/// This CPU and memory intensive operation must run behind admission control
/// on a blocking worker, never directly on an asynchronous executor thread.
pub fn hash_password(password: &[u8]) -> Result<String, PasswordError> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|_| PasswordError)?;
    let salt = SaltString::encode_b64(&salt).map_err(|_| PasswordError)?;
    Argon2::default()
        .hash_password(password, &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| PasswordError)
}

/// Verifies an Argon2id PHC hash with bounded work factors.
/// Call this only behind the same admission control as [`hash_password`].
pub fn verify_password(password: &[u8], encoded: &str) -> Result<bool, PasswordError> {
    let hash = PasswordHash::new(encoded).map_err(|_| PasswordError)?;
    if hash.algorithm.as_str() != "argon2id" || hash.version != Some(19) {
        return Err(PasswordError);
    }
    let get = |name| hash.params.get_decimal(name).ok_or(PasswordError);
    let (memory, iterations, lanes) = (get("m")?, get("t")?, get("p")?);
    if memory > 65_536
        || iterations > 10
        || lanes > 4
        || memory < 8
        || iterations == 0
        || lanes == 0
    {
        return Err(PasswordError);
    }
    match Argon2::default().verify_password(password, &hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(_) => Err(PasswordError),
    }
}

pub mod signing;
