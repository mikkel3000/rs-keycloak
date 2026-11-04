//! Authenticated encryption for secrets that must be recoverable, such as
//! client secrets the admin API returns. The key is supplied by the operator.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Sealing or opening failed without disclosing key or plaintext material.
#[derive(Debug)]
pub struct SealError;

/// An AES-256-GCM key with a non-secret identifier stored beside ciphertexts.
pub struct SecretKey {
    key: LessSafeKey,
    key_id: String,
    random: SystemRandom,
}

impl SecretKey {
    /// Builds a key from exactly 32 bytes of operator-supplied key material.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SealError> {
        let key = UnboundKey::new(&AES_256_GCM, bytes).map_err(|_| SealError)?;
        // A digest of a uniformly random 256-bit key does not reveal the key.
        let digest = Sha256::digest([b"rs-keycloak secret key id\0".as_slice(), bytes].concat());
        Ok(Self {
            key: LessSafeKey::new(key),
            key_id: URL_SAFE_NO_PAD.encode(&digest[..12]),
            random: SystemRandom::new(),
        })
    }

    /// Returns the identifier recorded with each ciphertext.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Encrypts `plaintext` bound to `context`; returns nonce then ciphertext.
    /// The same context must be supplied to [`SecretKey::open`].
    pub fn seal(&self, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>, SealError> {
        let mut nonce = [0u8; NONCE_LEN];
        self.random.fill(&mut nonce).map_err(|_| SealError)?;
        // Encrypt in place so no plaintext copy outlives this call.
        let mut body = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(context),
                &mut body,
            )
            .map_err(|_| SealError)?;
        let mut sealed = Vec::with_capacity(NONCE_LEN + body.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&body);
        Ok(sealed)
    }

    /// Decrypts a value from [`SecretKey::seal`] after checking its context.
    pub fn open(&self, sealed: &[u8], context: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
        if sealed.len() < NONCE_LEN + AES_256_GCM.tag_len() {
            return Err(SealError);
        }
        let (nonce, body) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| SealError)?;
        let mut body = Zeroizing::new(body.to_vec());
        let plaintext_len = self
            .key
            .open_in_place(nonce, Aad::from(context), &mut body)
            .map_err(|_| SealError)?
            .len();
        body.truncate(plaintext_len);
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::SecretKey;

    #[test]
    fn opens_only_with_the_same_key_and_context() {
        let key = SecretKey::from_bytes(&[7; 32]).expect("valid key length");
        let sealed = key.seal(b"client secret", b"realm\0client").expect("seal");
        assert_ne!(&sealed[12..sealed.len() - 16], b"client secret");
        let opened = key.open(&sealed, b"realm\0client").expect("open");
        assert_eq!(opened.as_slice(), b"client secret");
        assert!(key.open(&sealed, b"realm\0other").is_err());
        let other = SecretKey::from_bytes(&[8; 32]).expect("valid key length");
        assert!(other.open(&sealed, b"realm\0client").is_err());
        assert_ne!(key.key_id(), other.key_id());
        let mut tampered = sealed.clone();
        tampered[20] ^= 1;
        assert!(key.open(&tampered, b"realm\0client").is_err());
        assert!(key.open(&sealed[..20], b"realm\0client").is_err());
    }

    #[test]
    fn rejects_keys_that_are_not_256_bits() {
        assert!(SecretKey::from_bytes(&[0; 16]).is_err());
        assert!(SecretKey::from_bytes(&[0; 33]).is_err());
    }
}
