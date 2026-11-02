//! Stable RSA signing key loaded from externally supplied PKCS#8 DER.
//! Key distribution and rotation are the deployment operator's responsibility.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Signing or key parsing failed without disclosing key material.
#[derive(Debug)]
pub struct SigningError;

/// An externally provisioned key used for JWT signatures.
pub struct SigningKey {
    key: RsaKeyPair,
    key_id: String,
    n: String,
    e: String,
}

/// Public JSON Web Key for the active signing key.
#[derive(Serialize)]
pub struct PublicJwk {
    kty: &'static str,
    alg: &'static str,
    #[serde(rename = "use")]
    key_use: &'static str,
    kid: String,
    n: String,
    e: String,
}

/// Claims that must be checked against the committed authorization grant.
#[derive(Serialize)]
pub struct TokenClaims<'a> {
    /// Public issuer URL.
    pub iss: &'a str,
    /// Stable user subject.
    pub sub: &'a str,
    /// Intended audience.
    pub aud: &'a str,
    /// Unix issued-at seconds.
    pub iat: u64,
    /// Unix expiry seconds.
    pub exp: u64,
    /// Unique token ID.
    pub jti: &'a str,
    /// Authorized client ID.
    pub azp: &'a str,
    /// Granted scopes.
    pub scope: &'a str,
}

impl SigningKey {
    /// Loads a persistent externally provisioned RSA PKCS#8 private key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, SigningError> {
        let key = RsaKeyPair::from_pkcs8(der).map_err(|_| SigningError)?;
        let public_der = key.public_key().as_ref();
        let public = pkcs1::RsaPublicKey::try_from(public_der).map_err(|_| SigningError)?;
        if key.public().modulus_len() < 256 {
            return Err(SigningError);
        }
        let n = URL_SAFE_NO_PAD.encode(public.modulus.as_bytes());
        let e = URL_SAFE_NO_PAD.encode(public.public_exponent.as_bytes());
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(public_der));
        Ok(Self { key, key_id, n, e })
    }

    /// Returns the public signing key; never includes private key material.
    pub fn public_jwk(&self) -> PublicJwk {
        PublicJwk {
            kty: "RSA",
            alg: "RS256",
            key_use: "sig",
            kid: self.key_id.clone(),
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }

    /// Signs validated claims as a compact RS256 JWT.
    pub fn sign(&self, claims: &TokenClaims<'_>) -> Result<String, SigningError> {
        #[derive(Serialize)]
        struct Header<'a> {
            alg: &'static str,
            typ: &'static str,
            kid: &'a str,
        }
        let header = serde_json::to_vec(&Header {
            alg: "RS256",
            typ: "JWT",
            kid: &self.key_id,
        })
        .map_err(|_| SigningError)?;
        let claims = serde_json::to_vec(claims).map_err(|_| SigningError)?;
        let payload = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                payload.as_bytes(),
                &mut signature,
            )
            .map_err(|_| SigningError)?;
        Ok(format!("{}.{}", payload, URL_SAFE_NO_PAD.encode(signature)))
    }
}
