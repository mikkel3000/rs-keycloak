//! Stable RSA signing key loaded from externally supplied PKCS#8 DER.
//! Key distribution and rotation are the deployment operator's responsibility.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use pkcs1::der::Encode;
use pkcs1::der::asn1::BitStringRef;
use ring::rand::SystemRandom;
use ring::signature::{
    KeyPair, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RsaKeyPair, UnparsedPublicKey,
};
use ring::{hkdf, hmac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoRef;

/// Signing or key parsing failed without disclosing key material.
#[derive(Debug)]
pub struct SigningError;

/// An externally provisioned key used for JWT signatures.
pub struct SigningKey {
    key: RsaKeyPair,
    key_id: String,
    n: String,
    e: String,
    public_key_info: String,
    /// Authenticates state handed to browsers; derived from the private key
    /// so every instance holding the key accepts it.
    state_key: hmac::Key,
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
    /// Session identifier; service-account tokens have no stored session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<&'a str>,
    /// Granted scopes.
    pub scope: &'a str,
    /// Effective realm roles, as Keycloak's `realm_access` claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_access: Option<RealmAccess<'a>>,
    /// Effective client roles by client, as Keycloak's `resource_access`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_access: Option<std::collections::BTreeMap<&'a str, RealmAccess<'a>>>,
    /// Profile and email claims of the granted scopes.
    #[serde(flatten)]
    pub user: UserClaims<'a>,
}

/// The user claims of the `profile` and `email` scopes; each is left out
/// when its scope was not granted or the user has no value.
#[derive(Default, Serialize)]
pub struct UserClaims<'a> {
    /// Username, from the `profile` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<&'a str>,
    /// Given and family name joined, from the `profile` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Given name, from the `profile` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<&'a str>,
    /// Family name, from the `profile` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<&'a str>,
    /// Email address, from the `email` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<&'a str>,
    /// Whether the email is verified, from the `email` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// The `realm_access` claim listing effective realm role names.
#[derive(Serialize)]
pub struct RealmAccess<'a> {
    /// Role names.
    pub roles: &'a [String],
}

/// ID token values bound to an authorized OpenID Connect session.
#[derive(Serialize)]
pub struct IdTokenClaims<'a> {
    /// Issuer URL.
    pub iss: &'a str,
    /// Stable user ID.
    pub sub: &'a str,
    /// Client audience.
    pub aud: &'a str,
    /// Token creation time.
    pub iat: u64,
    /// Token expiration time.
    pub exp: u64,
    /// Session authentication time; absent when no user authenticated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// Client-provided OIDC nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<&'a str>,
    /// Session identifier, used as `id_token_hint` at logout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<&'a str>,
    /// Profile and email claims of the granted scopes.
    #[serde(flatten)]
    pub user: UserClaims<'a>,
}

/// Verified ID token claims used to resolve a logout request.
#[derive(Deserialize)]
pub struct VerifiedIdToken {
    #[serde(rename = "typ")]
    token_type: String,
    /// Issuer URL.
    pub iss: String,
    /// User subject.
    pub sub: String,
    /// Client audience.
    pub aud: String,
    /// Session ID, absent from service-account ID tokens.
    #[serde(default)]
    pub sid: Option<String>,
}

/// Verified token claims; callers must check issuer, audience, time and session state.
#[derive(Deserialize)]
pub struct VerifiedToken {
    #[serde(rename = "typ")]
    token_type: String,
    /// Issuer URL.
    pub iss: String,
    /// User subject.
    pub sub: String,
    /// Intended client audience.
    pub aud: String,
    /// Issue time.
    pub iat: u64,
    /// Expiry time.
    pub exp: u64,
    /// Unique token identifier.
    pub jti: String,
    /// Authorized client.
    pub azp: String,
    /// Session ID, absent from service-account tokens.
    #[serde(default)]
    pub sid: Option<String>,
    /// Granted scopes.
    pub scope: String,
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
        let info = SubjectPublicKeyInfoRef {
            algorithm: pkcs1::ALGORITHM_ID,
            subject_public_key: BitStringRef::from_bytes(public_der).map_err(|_| SigningError)?,
        };
        let public_key_info = STANDARD.encode(info.to_der().map_err(|_| SigningError)?);
        let state_key = hkdf::Salt::new(hkdf::HKDF_SHA256, b"rs-keycloak")
            .extract(der)
            .expand(&[b"browser state"], hmac::HMAC_SHA256)
            .map_err(|_| SigningError)?
            .into();
        Ok(Self {
            key,
            key_id,
            n,
            e,
            public_key_info,
            state_key,
        })
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

    /// The base64url tag that authenticates state handed to a browser.
    pub fn seal_state(&self, state: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(hmac::sign(&self.state_key, state))
    }

    /// Whether `tag` is the tag `seal_state` gives `state`.
    pub fn state_is_sealed(&self, state: &[u8], tag: &str) -> bool {
        URL_SAFE_NO_PAD
            .decode(tag)
            .is_ok_and(|tag| hmac::verify(&self.state_key, state, &tag).is_ok())
    }

    /// The key identifier published in the JWKS.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The public key as base64 DER SubjectPublicKeyInfo, the form the
    /// reference's admin keys listing uses.
    pub fn public_key_info(&self) -> &str {
        &self.public_key_info
    }

    /// Verifies a compact access token against this key and its exact header.
    pub fn verify_access_token(&self, token: &str) -> Result<VerifiedToken, SigningError> {
        let claims: VerifiedToken = self.verify_token(token)?;
        if claims.token_type != "Bearer" {
            return Err(SigningError);
        }
        Ok(claims)
    }

    /// Verifies a signed refresh token and rejects other token types.
    pub fn verify_refresh_token(&self, token: &str) -> Result<VerifiedToken, SigningError> {
        let claims: VerifiedToken = self.verify_token(token)?;
        if !matches!(claims.token_type.as_str(), "Refresh" | "Offline") {
            return Err(SigningError);
        }
        Ok(claims)
    }

    /// Verifies an ID token's signature and type. Expiry is not checked,
    /// because an expired ID token is still a valid logout hint.
    pub fn verify_id_token(&self, token: &str) -> Result<VerifiedIdToken, SigningError> {
        let claims: VerifiedIdToken = self.verify_token(token)?;
        if claims.token_type != "ID" {
            return Err(SigningError);
        }
        Ok(claims)
    }

    /// Verifies the signature and reads the token type; no grant is authorized by this alone.
    pub fn verify_token_type(&self, token: &str) -> Result<String, SigningError> {
        #[derive(Deserialize)]
        struct TokenType {
            typ: String,
        }
        Ok(self.verify_token::<TokenType>(token)?.typ)
    }

    fn verify_token<T: serde::de::DeserializeOwned>(&self, token: &str) -> Result<T, SigningError> {
        if token.len() > 8192 {
            return Err(SigningError);
        }
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(SigningError);
        };
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Header {
            alg: String,
            typ: String,
            kid: String,
        }
        let parsed: Header =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).map_err(|_| SigningError)?)
                .map_err(|_| SigningError)?;
        if parsed.alg != "RS256" || parsed.typ != "JWT" || parsed.kid != self.key_id {
            return Err(SigningError);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| SigningError)?;
        let message = format!("{header}.{payload}");
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, self.key.public_key().as_ref())
            .verify(message.as_bytes(), &signature)
            .map_err(|_| SigningError)?;
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).map_err(|_| SigningError)?)
            .map_err(|_| SigningError)
    }

    /// Signs validated claims as a compact RS256 JWT.
    pub fn sign(&self, claims: &TokenClaims<'_>) -> Result<String, SigningError> {
        self.sign_typed_claims(claims, "Bearer")
    }

    /// Signs refresh claims bound to a persisted refresh family.
    pub fn sign_refresh_token(&self, claims: &TokenClaims<'_>) -> Result<String, SigningError> {
        self.sign_typed_claims(claims, "Refresh")
    }

    /// Signs an offline refresh token, typed `Offline` as in the reference.
    pub fn sign_offline_token(&self, claims: &TokenClaims<'_>) -> Result<String, SigningError> {
        self.sign_typed_claims(claims, "Offline")
    }

    fn sign_typed_claims(
        &self,
        claims: &impl Serialize,
        typ: &str,
    ) -> Result<String, SigningError> {
        #[derive(Serialize)]
        struct TypedClaims<'a, T> {
            typ: &'a str,
            #[serde(flatten)]
            claims: &'a T,
        }
        self.sign_claims(&TypedClaims { typ, claims })
    }

    /// Signs a validated OpenID Connect ID token.
    pub fn sign_id_token(&self, claims: &IdTokenClaims<'_>) -> Result<String, SigningError> {
        self.sign_typed_claims(claims, "ID")
    }

    fn sign_claims(&self, claims: &impl Serialize) -> Result<String, SigningError> {
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
