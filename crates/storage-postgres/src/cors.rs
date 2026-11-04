//! Exact, realm-scoped client web origins.

use crate::{Storage, StorageError};

impl Storage {
    /// Add an origin to an enabled client, without changing an existing registration.
    ///
    /// Callers must validate and canonicalize the origin before calling this method.
    /// Returns false if the realm or client does not exist or is disabled.
    pub async fn add_client_web_origin(
        &self,
        realm: &str,
        client_identifier: &str,
        origin: &str,
    ) -> Result<bool, StorageError> {
        if origin.is_empty() || origin.len() > 2048 || origin == "*" || origin == "null" {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let client: Option<String> = sqlx::query_scalar("SELECT c.id FROM clients c JOIN realms r ON r.id = c.realm_id WHERE c.realm_id = $1 AND c.client_id = $2 AND c.enabled AND r.enabled FOR SHARE OF c, r")
            .bind(realm).bind(client_identifier).fetch_optional(&mut *conn).await?;
        let Some(client) = client else {
            tx.commit().await?;
            return Ok(false);
        };
        sqlx::query("INSERT INTO client_web_origins (realm_id, client_id, origin) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(realm).bind(client).bind(origin).execute(&mut *conn).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Check an exact origin against the enabled realm and client on the primary.
    pub async fn client_web_origin_allowed(
        &self,
        realm: &str,
        client_identifier: &str,
        origin: &str,
    ) -> Result<bool, StorageError> {
        if origin.is_empty() || origin.len() > 2048 || origin == "*" || origin == "null" {
            return Ok(false);
        }
        let mut tx = self.begin_request(true).await?;
        let allowed = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM client_web_origins o JOIN clients c ON c.realm_id = o.realm_id AND c.id = o.client_id JOIN realms r ON r.id = c.realm_id WHERE o.realm_id = $1 AND c.client_id = $2 AND o.origin = $3 COLLATE \"C\" AND c.enabled AND r.enabled)")
            .bind(realm).bind(client_identifier).bind(origin).fetch_one(tx.connection()).await?;
        tx.commit().await?;
        Ok(allowed)
    }
    /// Check a preflight origin against any enabled client in the realm.
    /// Actual requests must check their own client separately.
    pub async fn any_client_web_origin_allowed(
        &self,
        realm: &str,
        origin: &str,
    ) -> Result<bool, StorageError> {
        if origin.is_empty() || origin.len() > 2048 || origin == "*" || origin == "null" {
            return Ok(false);
        }
        let mut tx = self.begin_request(true).await?;
        let allowed = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM client_web_origins o JOIN clients c ON c.realm_id = o.realm_id AND c.id = o.client_id JOIN realms r ON r.id = c.realm_id WHERE o.realm_id = $1 AND o.origin = $2 COLLATE \"C\" AND c.enabled AND r.enabled)")
            .bind(realm).bind(origin).fetch_one(tx.connection()).await?;
        tx.commit().await?;
        Ok(allowed)
    }
}
