//! OAuth client authentication input parsing.

use axum::http::{HeaderMap, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use percent_encoding::percent_decode;
use rs_keycloak_crypto::secret_box::SecretKey;
use rs_keycloak_storage_postgres::client_secret_context;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Parsed public or confidential client credentials.
pub enum ClientCredentials {
    /// A public client sends only its identifier.
    Public(String),
    /// A confidential client sends its identifier and secret.
    Confidential {
        client_id: String,
        secret: Zeroizing<Vec<u8>>,
    },
}

/// Client authentication that cannot identify a client.
#[derive(Debug)]
pub enum InvalidClientAuthentication {
    /// No Authorization header and no `client_id` parameter were sent.
    Missing,
    /// Credentials were malformed, ambiguous, or used an unsupported scheme.
    Malformed,
}

fn form_decode(input: &str) -> Result<String, InvalidClientAuthentication> {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return Err(InvalidClientAuthentication::Malformed);
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    let text = Zeroizing::new(input.replace('+', " "));
    percent_decode(text.as_bytes())
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| InvalidClientAuthentication::Malformed)
}

/// Parses one authentication method, rejecting multiple Authorization headers
/// or conflicting basic and form credentials.
pub fn parse(
    headers: &HeaderMap,
    client_id: Option<String>,
    client_secret: Option<Zeroizing<String>>,
) -> Result<ClientCredentials, InvalidClientAuthentication> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let header = values.next();
    if values.next().is_some() {
        return Err(InvalidClientAuthentication::Malformed);
    }
    if let Some(header) = header {
        if client_secret.is_some() {
            return Err(InvalidClientAuthentication::Malformed);
        }
        let value = header
            .to_str()
            .map_err(|_| InvalidClientAuthentication::Malformed)?;
        let (scheme, value) = value
            .split_once(' ')
            .ok_or(InvalidClientAuthentication::Malformed)?;
        if !scheme.eq_ignore_ascii_case("basic") || value.len() > 8192 {
            return Err(InvalidClientAuthentication::Malformed);
        }
        let decoded = Zeroizing::new(
            STANDARD
                .decode(value)
                .map_err(|_| InvalidClientAuthentication::Malformed)?,
        );
        let decoded =
            std::str::from_utf8(&decoded).map_err(|_| InvalidClientAuthentication::Malformed)?;
        let (id, secret) = decoded
            .split_once(':')
            .ok_or(InvalidClientAuthentication::Malformed)?;
        if secret.contains(':') {
            return Err(InvalidClientAuthentication::Malformed);
        }
        let id = form_decode(id)?;
        let secret = Zeroizing::new(form_decode(secret)?.into_bytes());
        if id.is_empty()
            || id.len() > 255
            || secret.is_empty()
            || secret.len() > 1024
            || client_id.as_ref().is_some_and(|body| body != &id)
        {
            return Err(InvalidClientAuthentication::Malformed);
        }
        Ok(ClientCredentials::Confidential {
            client_id: id,
            secret,
        })
    } else {
        let id = match client_id {
            None => return Err(InvalidClientAuthentication::Missing),
            Some(id) if id.is_empty() => return Err(InvalidClientAuthentication::Missing),
            Some(id) if id.len() > 255 => return Err(InvalidClientAuthentication::Malformed),
            Some(id) => id,
        };
        match client_secret {
            Some(secret) if !secret.is_empty() && secret.len() <= 1024 => {
                Ok(ClientCredentials::Confidential {
                    client_id: id,
                    secret: Zeroizing::new(secret.as_bytes().to_vec()),
                })
            }
            Some(_) => Err(InvalidClientAuthentication::Malformed),
            None => Ok(ClientCredentials::Public(id)),
        }
    }
}

/// Authenticated client binding to be rechecked during the token transaction.
pub struct AuthenticatedClient {
    /// Public client identifier.
    pub client_id: String,
    /// Confidential client revision, or `None` for a public client.
    pub revision: Option<i64>,
}

/// Client authentication result matching the public OAuth error distinction.
pub enum ClientAuthResult {
    /// Credentials identify an enabled client.
    Authenticated(AuthenticatedClient),
    /// Client identifier is unknown or disabled.
    Unknown,
    /// An enabled client did not authenticate successfully.
    Unauthorized,
}

/// Verifies client credentials with bounded password work.
pub struct ClientAuthenticator {
    storage: std::sync::Arc<rs_keycloak_storage_postgres::Storage>,
    verifier: rs_keycloak_authentication::PasswordVerifier,
    secret_key: Option<std::sync::Arc<SecretKey>>,
}

impl ClientAuthenticator {
    /// Creates a bounded verifier for a running server.
    /// `secret_key` opens sealed client secrets; without it, clients with
    /// sealed secrets cannot authenticate and the request is unavailable.
    pub async fn new(
        storage: std::sync::Arc<rs_keycloak_storage_postgres::Storage>,
        secret_key: Option<std::sync::Arc<SecretKey>>,
    ) -> Result<Self, rs_keycloak_authentication::PasswordWorkError> {
        let verifier = rs_keycloak_authentication::PasswordVerifier::new().await?;
        Ok(Self {
            storage,
            verifier,
            secret_key,
        })
    }

    /// Authenticates a client; token transactions must recheck `revision`.
    pub async fn authenticate(
        &self,
        realm: &str,
        credentials: ClientCredentials,
    ) -> Result<ClientAuthResult, rs_keycloak_authentication::PasswordWorkError> {
        use rs_keycloak_authentication::PasswordWorkError;
        use rs_keycloak_storage_postgres::ClientAuthMaterial;
        let client_id = match &credentials {
            ClientCredentials::Public(id) => id,
            ClientCredentials::Confidential { client_id, .. } => client_id,
        };
        let material = self
            .storage
            .client_auth_material(realm, client_id)
            .await
            .map_err(|_| PasswordWorkError)?;
        match (credentials, material) {
            (ClientCredentials::Public(client_id), Some(ClientAuthMaterial::Public)) => {
                Ok(ClientAuthResult::Authenticated(AuthenticatedClient {
                    client_id,
                    revision: None,
                }))
            }
            (
                ClientCredentials::Confidential { client_id, secret },
                Some(ClientAuthMaterial::Confidential {
                    secret_phc,
                    revision,
                }),
            ) => {
                let hash = std::str::from_utf8(&secret_phc).map_err(|_| PasswordWorkError)?;
                if self.verifier.verify(secret, Some(hash)).await? {
                    Ok(ClientAuthResult::Authenticated(AuthenticatedClient {
                        client_id,
                        revision: Some(revision),
                    }))
                } else {
                    Ok(ClientAuthResult::Unauthorized)
                }
            }
            (
                ClientCredentials::Confidential { client_id, secret },
                Some(ClientAuthMaterial::Sealed {
                    client_id: internal_id,
                    sealed,
                    key_id,
                    revision,
                }),
            ) => {
                let key = self
                    .secret_key
                    .as_ref()
                    .filter(|key| key.key_id() == key_id)
                    .ok_or(PasswordWorkError)?;
                let stored = key
                    .open(&sealed, &client_secret_context(realm, &internal_id))
                    .map_err(|_| PasswordWorkError)?;
                // Comparing digests keeps the timing independent of the secret.
                if Sha256::digest(stored.as_slice()) == Sha256::digest(secret.as_slice()) {
                    Ok(ClientAuthResult::Authenticated(AuthenticatedClient {
                        client_id,
                        revision: Some(revision),
                    }))
                } else {
                    Ok(ClientAuthResult::Unauthorized)
                }
            }
            (ClientCredentials::Confidential { secret, .. }, material) => {
                self.verifier.verify(secret, None).await?;
                Ok(if material.is_some() {
                    ClientAuthResult::Unauthorized
                } else {
                    ClientAuthResult::Unknown
                })
            }
            (ClientCredentials::Public(_), None) => Ok(ClientAuthResult::Unknown),
            (ClientCredentials::Public(_), Some(_)) => Ok(ClientAuthResult::Unauthorized),
        }
    }
}
