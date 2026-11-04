//! Single-use action tokens sent by email, stored only as digests.

use crate::{Storage, StorageError};

/// What a redeemed password token was bound to.
pub struct RedeemedToken {
    /// User whose password changed.
    pub user_id: String,
    /// Login request the token was sent from, if any.
    pub authorization_request_id: Option<String>,
}

/// A live action token's user and pending actions.
pub struct ActionToken {
    /// User the actions apply to.
    pub user_id: String,
    /// Required actions to perform.
    pub actions: Vec<String>,
    /// Whether the token was requested from a login page.
    pub from_login: bool,
}

impl Storage {
    /// Stores a new action token digest for a user.
    pub async fn issue_action_token(
        &self,
        realm_id: &str,
        user_id: &str,
        token_hash: &[u8],
        actions: &[String],
        lifespan_seconds: i32,
        authorization_request_id: Option<&str>,
    ) -> Result<bool, StorageError> {
        if token_hash.len() != 32 || actions.is_empty() || lifespan_seconds <= 0 {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        sqlx::query("DELETE FROM action_tokens WHERE token_hash IN (SELECT token_hash FROM action_tokens WHERE expires_at <= clock_timestamp() ORDER BY expires_at LIMIT 16 FOR UPDATE SKIP LOCKED)")
            .execute(&mut *conn).await?;
        let issued = sqlx::query("INSERT INTO action_tokens (token_hash, realm_id, user_id, actions, expires_at, authorization_request_id) SELECT $1, u.realm_id, u.id, $4, clock_timestamp() + make_interval(secs => $5), $6 FROM users u WHERE u.realm_id = $2 AND u.id = $3 AND u.enabled")
            .bind(token_hash).bind(realm_id).bind(user_id).bind(actions).bind(f64::from(lifespan_seconds)).bind(authorization_request_id)
            .execute(&mut *conn).await?.rows_affected();
        tx.commit().await?;
        Ok(issued == 1)
    }

    /// Returns an unused, unexpired action token of an enabled user.
    pub async fn action_token(
        &self,
        realm_id: &str,
        token_hash: &[u8],
    ) -> Result<Option<ActionToken>, StorageError> {
        if token_hash.len() != 32 {
            return Ok(None);
        }
        let mut tx = self.begin_request(true).await?;
        let row: Option<(String, Vec<String>, bool)> = sqlx::query_as("SELECT t.user_id, t.actions, t.authorization_request_id IS NOT NULL FROM action_tokens t JOIN users u ON u.realm_id = t.realm_id AND u.id = t.user_id WHERE t.token_hash = $1 AND t.realm_id = $2 AND t.used_at IS NULL AND t.expires_at > clock_timestamp() AND u.enabled")
            .bind(token_hash).bind(realm_id).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        Ok(row.map(|(user_id, actions, from_login)| ActionToken {
            user_id,
            actions,
            from_login,
        }))
    }

    /// Uses an UPDATE_PASSWORD token once: replaces the user's password and
    /// clears the required action in the same transaction.
    pub async fn redeem_password_token(
        &self,
        realm_id: &str,
        token_hash: &[u8],
        credential_id: &str,
        password_phc: &[u8],
    ) -> Result<Option<RedeemedToken>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let row: Option<(String, Option<String>)> = sqlx::query_as("UPDATE action_tokens SET used_at = clock_timestamp() WHERE token_hash = $1 AND realm_id = $2 AND used_at IS NULL AND expires_at > clock_timestamp() AND 'UPDATE_PASSWORD' = ANY(actions) RETURNING user_id, authorization_request_id")
            .bind(token_hash).bind(realm_id).fetch_optional(&mut *conn).await?;
        let Some((user, authorization_request_id)) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        sqlx::query("DELETE FROM credentials WHERE realm_id = $1 AND user_id = $2 AND credential_type = 'password'")
            .bind(realm_id).bind(&user).execute(&mut *conn).await?;
        sqlx::query("INSERT INTO credentials (realm_id, id, user_id, credential_type, secret_data) VALUES ($1, $2, $3, 'password', $4)")
            .bind(realm_id).bind(credential_id).bind(&user).bind(password_phc).execute(&mut *conn).await?;
        sqlx::query("UPDATE users SET required_actions = array_remove(required_actions, 'UPDATE_PASSWORD') WHERE realm_id = $1 AND id = $2")
            .bind(realm_id).bind(&user).execute(&mut *conn).await?;
        tx.commit().await?;
        Ok(Some(RedeemedToken {
            user_id: user,
            authorization_request_id,
        }))
    }

    /// Finds the user a forgot-password request names, by username or email,
    /// if the realm allows resets and the user is enabled with an email.
    pub async fn reset_target(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<Option<(String, String)>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query_as("SELECT u.id, u.email FROM users u JOIN realms r ON r.id = u.realm_id WHERE u.realm_id = $1 AND r.reset_password_allowed AND u.enabled AND u.email IS NOT NULL AND u.service_account_client_id IS NULL AND (u.username_normalized = $2 OR u.email_normalized = $2) ORDER BY u.username_normalized = $2 DESC LIMIT 1")
            .bind(realm_id).bind(name.to_lowercase()).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Starts a session for a user who proved control of their email, bound
    /// to the login request whose CSRF digest matches, as password login
    /// would; pending login steps are flagged the same way.
    pub async fn start_session_for_request(
        &self,
        realm_id: &str,
        request_id: &str,
        csrf_hash: &[u8],
        user_id: &str,
        session_id: &str,
        session_ttl_seconds: i32,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let client: Option<String> = sqlx::query_scalar("SELECT client_id FROM authorization_requests WHERE id = $1 AND csrf_hash = $2 AND realm_id = $3 AND consumed_at IS NULL AND expires_at > clock_timestamp()")
            .bind(request_id).bind(csrf_hash).bind(realm_id).fetch_optional(&mut *conn).await?;
        let Some(client) = client else {
            tx.commit().await?;
            return Ok(false);
        };
        let created = sqlx::query("INSERT INTO user_sessions (realm_id, id, user_id, expires_at, steps_pending) SELECT $1, $2, $3, CURRENT_TIMESTAMP + make_interval(secs => $4), EXISTS (SELECT 1 FROM credentials c WHERE c.realm_id = $1 AND c.user_id = $3 AND c.credential_type = 'otp') OR cardinality(u.required_actions) > 0 FROM users u WHERE u.realm_id = $1 AND u.id = $3 AND u.enabled")
            .bind(realm_id).bind(session_id).bind(user_id).bind(f64::from(session_ttl_seconds))
            .execute(&mut *conn).await?.rows_affected();
        if created != 1 {
            tx.commit().await?;
            return Ok(false);
        }
        sqlx::query("INSERT INTO client_sessions (realm_id, id, user_session_id, client_id) VALUES ($1, $2, $2, $3)")
            .bind(realm_id).bind(session_id).bind(&client).execute(&mut *conn).await?;
        tx.commit().await?;
        Ok(true)
    }
}
