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

impl Storage {
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
