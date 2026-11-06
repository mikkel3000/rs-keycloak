//! A user's own account: authorization, profile and sessions.

use sqlx::Row;

use crate::login_steps::{Profile, save_profile};
use crate::{Storage, StorageError};

/// One of the user's active sessions.
pub struct AccountSession {
    /// Session identifier.
    pub id: String,
    /// Start time in Unix seconds.
    pub started: i64,
    /// Expiry time in Unix seconds.
    pub expires: i64,
    /// Public identifiers of the clients in the session, sorted.
    pub clients: Vec<String>,
}

/// A client the user uses, as the account console lists it.
pub struct AccountApplication {
    /// Public client identifier.
    pub client_identifier: String,
    /// Whether users must consent before the client receives a code.
    pub consent_required: bool,
    /// Root URL that the base URL resolves against.
    pub root_url: Option<String>,
    /// The client's home page, possibly relative to the root URL.
    pub base_url: Option<String>,
    /// Whether the caller's current session includes the client.
    pub in_use: bool,
    /// Whether the user has a live offline token for the client.
    pub offline: bool,
}

impl Storage {
    /// Lists the clients of the user's current session, and those the user
    /// has consented to or holds offline tokens for.
    pub async fn account_applications(
        &self,
        realm_id: &str,
        user_id: &str,
        session_id: &str,
    ) -> Result<Vec<AccountApplication>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query("SELECT * FROM (SELECT c.client_id, c.consent_required, c.root_url, c.base_url, EXISTS (SELECT 1 FROM client_sessions cs WHERE cs.realm_id = c.realm_id AND cs.client_id = c.id AND cs.user_session_id = $3) AS in_use, EXISTS (SELECT 1 FROM refresh_families f JOIN user_sessions us ON us.realm_id = f.realm_id AND us.id = f.user_session_id WHERE f.realm_id = c.realm_id AND f.client_id = c.id AND us.user_id = $2 AND f.offline AND f.revoked_at IS NULL AND f.expires_at > clock_timestamp()) AS offline, EXISTS (SELECT 1 FROM user_consents uc WHERE uc.realm_id = c.realm_id AND uc.client_id = c.id AND uc.user_id = $2) AS consented FROM clients c WHERE c.realm_id = $1 AND c.enabled) apps WHERE in_use OR offline OR consented ORDER BY client_id")
            .bind(realm_id).bind(user_id).bind(session_id).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| {
                Ok(AccountApplication {
                    client_identifier: row.try_get("client_id")?,
                    consent_required: row.try_get("consent_required")?,
                    root_url: row.try_get("root_url")?,
                    base_url: row.try_get("base_url")?,
                    in_use: row.try_get("in_use")?,
                    offline: row.try_get("offline")?,
                })
            })
            .collect()
    }

    /// Saves the user's own name and email; false if the email is taken.
    pub async fn update_account_profile(
        &self,
        realm_id: &str,
        user_id: &str,
        profile: &Profile,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let saved = save_profile(tx.connection(), realm_id, user_id, profile, false).await?;
        tx.commit().await?;
        Ok(saved)
    }

    /// Lists the user's active, fully authenticated sessions, newest first.
    pub async fn account_sessions(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Vec<AccountSession>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query("SELECT us.id, floor(EXTRACT(EPOCH FROM us.created_at))::bigint AS started, floor(EXTRACT(EPOCH FROM us.expires_at))::bigint AS expires, ARRAY(SELECT c.client_id FROM client_sessions cs JOIN clients c ON c.realm_id = cs.realm_id AND c.id = cs.client_id WHERE cs.realm_id = us.realm_id AND cs.user_session_id = us.id ORDER BY c.client_id) AS clients FROM user_sessions us WHERE us.realm_id = $1 AND us.user_id = $2 AND us.revoked_at IS NULL AND NOT us.steps_pending AND us.expires_at > clock_timestamp() ORDER BY us.created_at DESC")
            .bind(realm_id).bind(user_id).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| {
                Ok(AccountSession {
                    id: row.try_get("id")?,
                    started: row.try_get("started")?,
                    expires: row.try_get("expires")?,
                    clients: row.try_get("clients")?,
                })
            })
            .collect()
    }
}
