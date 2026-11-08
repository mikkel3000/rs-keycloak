//! Password work admission for the login service.
//!
//! This crate is not an HTTP login endpoint. Client registration, protocol
//! binding, and authorization-code issuance must precede public use.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use uuid::Uuid;
use zeroize::Zeroizing;

/// A bounded password verifier, shared by requests on one server instance.
pub struct PasswordVerifier {
    slots: Arc<Semaphore>,
    dummy_hash: Zeroizing<String>,
}

/// Password work could not be completed safely.
#[derive(Debug)]
pub struct PasswordWorkError;

impl PasswordVerifier {
    /// Creates a process-local dummy credential for unknown accounts.
    pub async fn new() -> Result<Self, PasswordWorkError> {
        let hash = tokio::task::spawn_blocking(|| {
            let dummy = Zeroizing::new(*Uuid::new_v4().as_bytes());
            rs_keycloak_crypto::hash_password(dummy.as_ref())
        })
        .await
        .map_err(|_| PasswordWorkError)?
        .map_err(|_| PasswordWorkError)?;
        Ok(Self {
            slots: Arc::new(Semaphore::new(2)),
            dummy_hash: Zeroizing::new(hash),
        })
    }

    /// Verifies a password or performs equivalent dummy work when no account
    /// exists. The permit stays with the blocking task even if its caller is
    /// cancelled, bounding memory and CPU across timeouts.
    pub async fn verify(
        &self,
        password: Zeroizing<Vec<u8>>,
        encoded: Option<&str>,
    ) -> Result<bool, PasswordWorkError> {
        if password.len() > 1024 {
            return Err(PasswordWorkError);
        }
        let permit = tokio::time::timeout(
            Duration::from_millis(250),
            Arc::clone(&self.slots).acquire_owned(),
        )
        .await
        .map_err(|_| PasswordWorkError)?
        .map_err(|_| PasswordWorkError)?;
        let known = encoded.is_some();
        let encoded = Zeroizing::new(encoded.unwrap_or(&self.dummy_hash).to_owned());
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            rs_keycloak_crypto::verify_password(&password, &encoded)
                .map(|valid| valid && known)
                .map_err(|_| PasswordWorkError)
        })
        .await
        .map_err(|_| PasswordWorkError)?
    }
}

/// Result of the internal password step; an authenticated session is not an
/// authorization code and must not be returned directly to an OAuth client.
pub enum LoginResult {
    /// Password authentication completed and the session was committed.
    Authenticated { session_id: String },
    /// Authentication failed without identifying the failed condition.
    Denied,
    /// The login is an email several users share, which the reference
    /// answers with `usernameExistsMessage` before checking a password.
    SharedEmail,
}

/// One password sign-in's context.
#[derive(Clone, Copy)]
pub struct LoginAttempt<'a> {
    /// The validated realm.
    pub realm_id: &'a str,
    /// The validated client.
    pub client_id: &'a str,
    /// The lowercased username or email entered.
    pub username_normalized: &'a str,
    /// Whether the user asked to be remembered.
    pub remember_me: bool,
    /// The client address, which brute-force detection records.
    pub address: Option<&'a str>,
}

/// Coordinates password work with guarded database state transitions.
pub struct LoginService {
    storage: Arc<rs_keycloak_storage_postgres::Storage>,
    verifier: PasswordVerifier,
}

impl LoginService {
    /// Creates the service after the storage and schema checks have succeeded.
    pub async fn new(
        storage: Arc<rs_keycloak_storage_postgres::Storage>,
    ) -> Result<Self, PasswordWorkError> {
        Ok(Self {
            storage,
            verifier: PasswordVerifier::new().await?,
        })
    }

    /// Authenticates a previously validated realm and client; callers must
    /// establish protocol, redirect, CSRF, and client bindings before use.
    pub async fn authenticate(
        &self,
        attempt: &LoginAttempt<'_>,
        password: Zeroizing<Vec<u8>>,
    ) -> Result<LoginResult, PasswordWorkError> {
        let LoginAttempt {
            realm_id,
            client_id,
            username_normalized,
            remember_me,
            address,
        } = *attempt;
        if password.len() > 1024 {
            return Err(PasswordWorkError);
        }
        match self
            .storage
            .shared_login_email(realm_id, username_normalized)
            .await
        {
            Ok(false) => (),
            Ok(true) => return Ok(LoginResult::SharedEmail),
            Err(_) => return Err(PasswordWorkError),
        }
        let challenge_id = Uuid::new_v4().to_string();
        let credential = self
            .storage
            .start_login(realm_id, client_id, username_normalized, &challenge_id, 120)
            .await;
        let credential = match credential {
            Ok(value) => value,
            Err(_) => {
                let _ = self.verifier.verify(password, None).await;
                return Err(PasswordWorkError);
            }
        };
        let Some(credential) = credential else {
            self.verifier.verify(password, None).await?;
            return Ok(LoginResult::Denied);
        };
        let hash = match std::str::from_utf8(&credential.phc) {
            Ok(hash) => hash,
            Err(_) => {
                let _ = self.verifier.verify(password, None).await;
                return Err(PasswordWorkError);
            }
        };
        let valid = self.verifier.verify(password, Some(hash)).await?;
        let session_id = Uuid::new_v4().to_string();
        match self
            .storage
            .finish_login(
                &challenge_id,
                credential.user_revision,
                credential.credential_revision,
                valid,
                &session_id,
                1800,
                remember_me,
                address,
            )
            .await
            .map_err(|_| PasswordWorkError)?
        {
            rs_keycloak_storage_postgres::LoginOutcome::Authenticated => {
                Ok(LoginResult::Authenticated { session_id })
            }
            rs_keycloak_storage_postgres::LoginOutcome::Denied => Ok(LoginResult::Denied),
        }
    }
}
