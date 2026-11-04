//! OAuth consent decisions bound to pending authorization requests.

use sqlx::Row;

use crate::{AuthorizationRedirect, Storage, StorageError};

/// A user's stored consent for one client.
pub struct ConsentRecord {
    /// Public client identifier.
    pub client_identifier: String,
    /// Granted scope string.
    pub scope: String,
    /// Creation time in Unix milliseconds.
    pub created: i64,
    /// Last update time in Unix milliseconds.
    pub updated: i64,
}

/// A pending authorization request waiting for the user's consent.
pub struct PendingConsent {
    /// Authenticated user session.
    pub session_id: String,
    /// Public client identifier, shown on the consent screen.
    pub client_identifier: String,
    /// Requested scope string.
    pub scope: String,
}

impl Storage {
    /// Reports whether a request must ask for consent before issuing a code:
    /// the client requires consent and either `prompt=consent` was sent or
    /// the session's user has not consented to this client yet.
    pub async fn consent_needed(
        &self,
        request_id: &str,
        csrf_hash: &[u8],
        session_id: &str,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let needed: Option<bool> = sqlx::query_scalar("SELECT c.consent_required AND (a.prompt_consent OR NOT EXISTS (SELECT 1 FROM user_consents uc WHERE uc.realm_id = a.realm_id AND uc.user_id = us.user_id AND uc.client_id = a.client_id)) FROM authorization_requests a JOIN clients c ON c.realm_id = a.realm_id AND c.id = a.client_id JOIN user_sessions us ON us.realm_id = a.realm_id AND us.id = $3 WHERE a.id = $1 AND a.csrf_hash = $2 AND a.consumed_at IS NULL AND a.expires_at > clock_timestamp()")
            .bind(request_id).bind(csrf_hash).bind(session_id).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        Ok(needed.unwrap_or(false))
    }

    /// Records the authenticated session on a request that awaits consent.
    pub async fn await_consent(
        &self,
        request_id: &str,
        csrf_hash: &[u8],
        session_id: &str,
    ) -> Result<Option<PendingConsent>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query("UPDATE authorization_requests a SET pending_session_id = $3 FROM clients c WHERE c.realm_id = a.realm_id AND c.id = a.client_id AND a.id = $1 AND a.csrf_hash = $2 AND a.consumed_at IS NULL AND a.expires_at > clock_timestamp() RETURNING c.client_id, a.scope")
            .bind(request_id).bind(csrf_hash).bind(session_id).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        row.map(|row| {
            Ok(PendingConsent {
                session_id: session_id.to_owned(),
                client_identifier: row.try_get("client_id")?,
                scope: row.try_get("scope")?,
            })
        })
        .transpose()
    }

    /// Returns the session waiting on a request's consent screen.
    pub async fn pending_consent(
        &self,
        request_id: &str,
        csrf_hash: &[u8],
    ) -> Result<Option<PendingConsent>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query("SELECT a.pending_session_id, c.client_id, a.scope FROM authorization_requests a JOIN clients c ON c.realm_id = a.realm_id AND c.id = a.client_id JOIN user_sessions us ON us.realm_id = a.realm_id AND us.id = a.pending_session_id WHERE a.id = $1 AND a.csrf_hash = $2 AND a.consumed_at IS NULL AND a.expires_at > clock_timestamp() AND us.revoked_at IS NULL AND us.expires_at > clock_timestamp()")
            .bind(request_id).bind(csrf_hash).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        row.map(|row| {
            Ok(PendingConsent {
                session_id: row.try_get("pending_session_id")?,
                client_identifier: row.try_get("client_id")?,
                scope: row.try_get("scope")?,
            })
        })
        .transpose()
    }

    /// Stores the user's consent for the request's client and scope.
    pub async fn grant_consent(
        &self,
        request_id: &str,
        csrf_hash: &[u8],
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let granted = sqlx::query("INSERT INTO user_consents (realm_id, user_id, client_id, scope) SELECT a.realm_id, us.user_id, a.client_id, a.scope FROM authorization_requests a JOIN user_sessions us ON us.realm_id = a.realm_id AND us.id = a.pending_session_id WHERE a.id = $1 AND a.csrf_hash = $2 AND a.consumed_at IS NULL AND a.expires_at > clock_timestamp() ON CONFLICT (realm_id, user_id, client_id) DO UPDATE SET scope = EXCLUDED.scope, updated_at = clock_timestamp()")
            .bind(request_id).bind(csrf_hash).execute(tx.connection()).await?.rows_affected();
        tx.commit().await?;
        Ok(granted == 1)
    }

    /// Consumes a request the user declined and returns where to report it.
    pub async fn deny_consent(
        &self,
        request_id: &str,
        csrf_hash: &[u8],
    ) -> Result<Option<AuthorizationRedirect>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query("UPDATE authorization_requests SET consumed_at = clock_timestamp() WHERE id = $1 AND csrf_hash = $2 AND consumed_at IS NULL AND expires_at > clock_timestamp() AND pending_session_id IS NOT NULL RETURNING redirect_uri, state, response_mode")
            .bind(request_id).bind(csrf_hash).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        row.map(|row| {
            Ok(AuthorizationRedirect {
                redirect_uri: row.try_get("redirect_uri")?,
                state: row.try_get("state")?,
                response_mode: row.try_get("response_mode")?,
            })
        })
        .transpose()
    }

    /// Lists a user's consents by client, or `None` if the user is missing.
    pub async fn user_consents(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Option<Vec<ConsentRecord>>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id = $2)",
        )
        .bind(realm_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;
        let consents = if exists {
            let rows = sqlx::query("SELECT c.client_id, uc.scope, (floor(EXTRACT(EPOCH FROM uc.created_at) * 1000))::bigint AS created, (floor(EXTRACT(EPOCH FROM uc.updated_at) * 1000))::bigint AS updated FROM user_consents uc JOIN clients c ON c.realm_id = uc.realm_id AND c.id = uc.client_id WHERE uc.realm_id = $1 AND uc.user_id = $2 ORDER BY c.client_id")
                .bind(realm_id).bind(user_id).fetch_all(&mut *conn).await?;
            Some(
                rows.iter()
                    .map(|row| {
                        Ok(ConsentRecord {
                            client_identifier: row.try_get("client_id")?,
                            scope: row.try_get("scope")?,
                            created: row.try_get("created")?,
                            updated: row.try_get("updated")?,
                        })
                    })
                    .collect::<Result<_, StorageError>>()?,
            )
        } else {
            None
        };
        tx.commit().await?;
        Ok(consents)
    }

    /// Revokes a user's consent for a client; false if there was none.
    pub async fn revoke_consent(
        &self,
        realm_id: &str,
        user_id: &str,
        client_identifier: &str,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let revoked = sqlx::query("DELETE FROM user_consents uc USING clients c WHERE c.realm_id = uc.realm_id AND c.id = uc.client_id AND uc.realm_id = $1 AND uc.user_id = $2 AND c.client_id = $3")
            .bind(realm_id).bind(user_id).bind(client_identifier).execute(tx.connection()).await?.rows_affected();
        tx.commit().await?;
        Ok(revoked > 0)
    }
}
