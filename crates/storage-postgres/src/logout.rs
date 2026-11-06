//! Ending user sessions at OIDC logout.

use sqlx::{PgConnection, Row};

use crate::{RedirectRules, Storage, StorageError, authenticated_client};

/// Outcome of a refresh-token logout.
pub enum RefreshLogout {
    /// The token's session is ended (now or by an earlier logout).
    Ended,
    /// No refresh token with this ID was issued to the client.
    UnknownToken,
}

/// Revokes a user session and every refresh family bound to it.
/// Ends a login session and its online refresh families; offline families
/// outlive it, as in the reference.
pub(crate) async fn end_session(
    connection: &mut PgConnection,
    realm_id: &str,
    session_id: &str,
) -> Result<(), StorageError> {
    sqlx::query("UPDATE refresh_families SET revoked_at = COALESCE(revoked_at, clock_timestamp()) WHERE realm_id = $1 AND user_session_id = $2 AND NOT offline")
        .bind(realm_id).bind(session_id).execute(&mut *connection).await?;
    sqlx::query("UPDATE user_sessions SET revoked_at = COALESCE(revoked_at, clock_timestamp()) WHERE realm_id = $1 AND id = $2")
        .bind(realm_id).bind(session_id).execute(&mut *connection).await?;
    Ok(())
}

impl Storage {
    /// Ends the session of a refresh token issued to an authenticated client.
    /// Repeating the logout with the same token is harmless.
    pub async fn logout_with_refresh_token(
        &self,
        realm_id: &str,
        client_identifier: &str,
        client_revision: Option<i64>,
        token_hash: &[u8],
    ) -> Result<RefreshLogout, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let client = authenticated_client(
            tx.connection(),
            realm_id,
            client_identifier,
            client_revision,
        )
        .await?;
        let conn = tx.connection();
        let session: Option<String> = sqlx::query_scalar("SELECT f.user_session_id FROM refresh_tokens t JOIN refresh_families f ON f.id = t.family_id WHERE t.token_hash = $1 AND f.realm_id = $2 AND f.client_id = $3")
            .bind(token_hash).bind(realm_id).bind(&client).fetch_optional(&mut *conn).await?;
        let result = match session {
            Some(session) => {
                end_session(conn, realm_id, &session).await?;
                RefreshLogout::Ended
            }
            None => RefreshLogout::UnknownToken,
        };
        tx.commit().await?;
        Ok(result)
    }

    /// Ends a user's session named by a verified ID token hint.
    pub async fn logout_session(
        &self,
        realm_id: &str,
        session_id: &str,
        user_id: &str,
    ) -> Result<(), StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let owned: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_sessions WHERE realm_id = $1 AND id = $2 AND user_id = $3 FOR UPDATE)")
            .bind(realm_id).bind(session_id).bind(user_id).fetch_one(&mut *conn).await?;
        if owned {
            end_session(conn, realm_id, session_id).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Reads the post-logout redirect URIs of an enabled client: its own
    /// list, plus its redirect URIs when it uses Keycloak's "+" or, as in
    /// the reference, has no post-logout URIs of its own.
    pub async fn post_logout_rules(
        &self,
        realm_id: &str,
        client_identifier: &str,
    ) -> Result<Option<RedirectRules>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query("SELECT c.root_url, c.bearer_only, ARRAY(SELECT p.redirect_uri FROM client_post_logout_redirect_uris p WHERE p.realm_id = c.realm_id AND p.client_id = c.id UNION SELECT d.redirect_uri FROM client_redirect_uris d WHERE (c.post_logout_uses_redirect_uris OR NOT EXISTS (SELECT 1 FROM client_post_logout_redirect_uris p WHERE p.realm_id = c.realm_id AND p.client_id = c.id)) AND d.realm_id = c.realm_id AND d.client_id = c.id ORDER BY 1) AS redirect_uris FROM clients c WHERE c.realm_id = $1 AND c.client_id = $2 AND c.enabled")
            .bind(realm_id).bind(client_identifier).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        row.map(|row| {
            Ok(RedirectRules {
                root_url: row.try_get("root_url")?,
                redirect_uris: row.try_get("redirect_uris")?,
                bearer_only: row.try_get("bearer_only")?,
            })
        })
        .transpose()
    }
}

impl Storage {
    /// Ends every other active session of the session's user, as the
    /// reference does when a required action's "logout-sessions" box is set.
    pub async fn end_other_sessions(
        &self,
        realm_id: &str,
        session_id: &str,
    ) -> Result<u64, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let others: Vec<String> = sqlx::query_scalar("SELECT o.id FROM user_sessions s JOIN user_sessions o ON o.realm_id = s.realm_id AND o.user_id = s.user_id AND o.id <> s.id WHERE s.realm_id = $1 AND s.id = $2 AND o.revoked_at IS NULL FOR UPDATE OF o")
            .bind(realm_id).bind(session_id).fetch_all(&mut *conn).await?;
        for other in &others {
            end_session(conn, realm_id, other).await?;
        }
        tx.commit().await?;
        Ok(others.len() as u64)
    }
}

impl Storage {
    /// Ends every active session of a user, with their refresh families.
    pub async fn end_user_sessions(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<u64, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let sessions: Vec<String> = sqlx::query_scalar("SELECT id FROM user_sessions WHERE realm_id = $1 AND user_id = $2 AND revoked_at IS NULL FOR UPDATE")
            .bind(realm_id).bind(user_id).fetch_all(&mut *conn).await?;
        for session in &sessions {
            end_session(conn, realm_id, session).await?;
        }
        tx.commit().await?;
        Ok(sessions.len() as u64)
    }
}
