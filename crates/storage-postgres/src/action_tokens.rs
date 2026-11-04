//! Single-use action tokens sent by email, stored only as digests.

use crate::{Storage, StorageError};

/// A live action token's user and pending actions.
pub struct ActionToken {
    /// User the actions apply to.
    pub user_id: String,
    /// Required actions to perform.
    pub actions: Vec<String>,
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
    ) -> Result<bool, StorageError> {
        if token_hash.len() != 32 || actions.is_empty() || lifespan_seconds <= 0 {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        sqlx::query("DELETE FROM action_tokens WHERE token_hash IN (SELECT token_hash FROM action_tokens WHERE expires_at <= clock_timestamp() ORDER BY expires_at LIMIT 16 FOR UPDATE SKIP LOCKED)")
            .execute(&mut *conn).await?;
        let issued = sqlx::query("INSERT INTO action_tokens (token_hash, realm_id, user_id, actions, expires_at) SELECT $1, u.realm_id, u.id, $4, clock_timestamp() + make_interval(secs => $5) FROM users u WHERE u.realm_id = $2 AND u.id = $3 AND u.enabled")
            .bind(token_hash).bind(realm_id).bind(user_id).bind(actions).bind(f64::from(lifespan_seconds))
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
        let row: Option<(String, Vec<String>)> = sqlx::query_as("SELECT t.user_id, t.actions FROM action_tokens t JOIN users u ON u.realm_id = t.realm_id AND u.id = t.user_id WHERE t.token_hash = $1 AND t.realm_id = $2 AND t.used_at IS NULL AND t.expires_at > clock_timestamp() AND u.enabled")
            .bind(token_hash).bind(realm_id).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        Ok(row.map(|(user_id, actions)| ActionToken { user_id, actions }))
    }

    /// Uses an UPDATE_PASSWORD token once: replaces the user's password and
    /// clears the required action in the same transaction.
    pub async fn redeem_password_token(
        &self,
        realm_id: &str,
        token_hash: &[u8],
        credential_id: &str,
        password_phc: &[u8],
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let user: Option<String> = sqlx::query_scalar("UPDATE action_tokens SET used_at = clock_timestamp() WHERE token_hash = $1 AND realm_id = $2 AND used_at IS NULL AND expires_at > clock_timestamp() AND 'UPDATE_PASSWORD' = ANY(actions) RETURNING user_id")
            .bind(token_hash).bind(realm_id).fetch_optional(&mut *conn).await?;
        let Some(user) = user else {
            tx.commit().await?;
            return Ok(false);
        };
        sqlx::query("DELETE FROM credentials WHERE realm_id = $1 AND user_id = $2 AND credential_type = 'password'")
            .bind(realm_id).bind(&user).execute(&mut *conn).await?;
        sqlx::query("INSERT INTO credentials (realm_id, id, user_id, credential_type, secret_data) VALUES ($1, $2, $3, 'password', $4)")
            .bind(realm_id).bind(credential_id).bind(&user).bind(password_phc).execute(&mut *conn).await?;
        sqlx::query("UPDATE users SET required_actions = array_remove(required_actions, 'UPDATE_PASSWORD') WHERE realm_id = $1 AND id = $2")
            .bind(realm_id).bind(&user).execute(&mut *conn).await?;
        tx.commit().await?;
        Ok(true)
    }
}
