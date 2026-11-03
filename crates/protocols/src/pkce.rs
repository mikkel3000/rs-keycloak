//! S256 PKCE verifier validation as defined in RFC 7636.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// A validated S256 code challenge bound to an authorization request.
pub struct Challenge([u8; 32]);

/// A malformed PKCE input.
#[derive(Debug)]
pub struct InvalidPkce;

impl Challenge {
    /// Parses a canonical, unpadded base64url SHA-256 challenge.
    pub fn parse(value: &str) -> Result<Self, InvalidPkce> {
        if value.len() != 43 {
            return Err(InvalidPkce);
        }
        let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| InvalidPkce)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| InvalidPkce)?;
        Ok(Self(bytes))
    }

    /// Returns the decoded SHA-256 challenge for storage.
    pub fn digest(&self) -> &[u8; 32] {
        &self.0
    }

    /// Checks the verifier using the S256 transform and constant-time comparison.
    pub fn verify(&self, verifier: &str) -> bool {
        if !(43..=128).contains(&verifier.len())
            || !verifier.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
            })
        {
            return false;
        }
        let digest = Sha256::digest(verifier.as_bytes());
        bool::from(self.0.ct_eq(digest.as_slice()))
    }
}

/// Computes the S256 digest for a syntactically valid verifier.
pub fn verifier_digest(verifier: &str) -> Option<[u8; 32]> {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return None;
    }
    Some(Sha256::digest(verifier.as_bytes()).into())
}

#[cfg(test)]
mod tests {
    use super::Challenge;

    #[test]
    fn rfc_7636_vector_and_rejections() {
        let challenge = Challenge::parse("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").unwrap();
        assert!(challenge.verify("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        assert!(!challenge.verify("eBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        assert!(!challenge.verify("short"));
        assert!(Challenge::parse("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM=").is_err());
    }
}
