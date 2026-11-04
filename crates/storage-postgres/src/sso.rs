//! Browser SSO sessions identified by the KEYCLOAK_IDENTITY cookie.

use crate::{Storage, StorageError};

/// An active SSO session found from its cookie token.
pub struct SsoSession {
    /// User session identifier, sent as `session_state`.
    pub session_id: String,
    /// Authentication time as Unix seconds, for `max_age`.
    pub auth_time: i64,
}

impl Storage {
    /// Binds a new SSO cookie token digest to a freshly authenticated session.
    pub async fn set_sso_token(
        &self,
        realm_id: &str,
        session_id: &str,
        token_hash: &[u8],
    ) -> Result<bool, StorageError> {
        if token_hash.len() != 32 {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(true).await?;
        let changed = sqlx::query("UPDATE user_sessions SET sso_token_hash = $3 WHERE realm_id = $1 AND id = $2 AND revoked_at IS NULL AND expires_at > clock_timestamp()")
            .bind(realm_id).bind(session_id).bind(token_hash).execute(tx.connection()).await?.rows_affected();
        tx.commit().await?;
        Ok(changed == 1)
    }

    /// Finds the active session of an SSO cookie token in a realm.
    pub async fn sso_session(
        &self,
        realm_id: &str,
        token_hash: &[u8],
    ) -> Result<Option<SsoSession>, StorageError> {
        if token_hash.len() != 32 {
            return Ok(None);
        }
        let mut tx = self.begin_request(true).await?;
        let row: Option<(String, i64)> = sqlx::query_as("SELECT us.id, floor(EXTRACT(EPOCH FROM us.created_at))::bigint FROM user_sessions us JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id JOIN realms r ON r.id = us.realm_id WHERE us.realm_id = $1 AND us.sso_token_hash = $2 AND us.revoked_at IS NULL AND us.expires_at > clock_timestamp() AND u.enabled AND r.enabled")
            .bind(realm_id).bind(token_hash).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        Ok(row.map(|(session_id, auth_time)| SsoSession {
            session_id,
            auth_time,
        }))
    }

    /// Adds a client to an active session so the session can issue it codes.
    pub async fn join_client_session(
        &self,
        realm_id: &str,
        session_id: &str,
        client_identifier: &str,
        client_session_id: &str,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let joined = sqlx::query("INSERT INTO client_sessions (realm_id, id, user_session_id, client_id) SELECT us.realm_id, $4, us.id, c.id FROM user_sessions us JOIN clients c ON c.realm_id = us.realm_id WHERE us.realm_id = $1 AND us.id = $2 AND c.client_id = $3 AND c.enabled AND us.revoked_at IS NULL AND us.expires_at > clock_timestamp() ON CONFLICT (realm_id, user_session_id, client_id) DO NOTHING")
            .bind(realm_id).bind(session_id).bind(client_identifier).bind(client_session_id).execute(tx.connection()).await?.rows_affected();
        let member = joined == 1 || sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM client_sessions cs JOIN clients c ON c.realm_id = cs.realm_id AND c.id = cs.client_id WHERE cs.realm_id = $1 AND cs.user_session_id = $2 AND c.client_id = $3)")
            .bind(realm_id).bind(session_id).bind(client_identifier).fetch_one(tx.connection()).await?;
        tx.commit().await?;
        Ok(member)
    }
}
