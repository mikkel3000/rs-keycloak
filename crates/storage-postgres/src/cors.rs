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

    /// Check an exact origin against a client's registered web origins.
    ///
    /// Unknown clients are reported separately because the reference allows
    /// every origin until a token names a client that exists.
    pub async fn client_web_origin(
        &self,
        realm: &str,
        client_identifier: &str,
        origin: &str,
    ) -> Result<WebOriginCheck, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let allowed: Option<bool> = sqlx::query_scalar("SELECT c.enabled AND r.enabled AND EXISTS (SELECT 1 FROM client_web_origins o WHERE o.realm_id = c.realm_id AND o.client_id = c.id AND o.origin = $3 COLLATE \"C\") FROM clients c JOIN realms r ON r.id = c.realm_id WHERE c.realm_id = $1 AND c.client_id = $2")
            .bind(realm).bind(client_identifier).bind(origin).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        Ok(match allowed {
            None => WebOriginCheck::UnknownClient,
            Some(true) if !matches!(origin, "" | "*" | "null") && origin.len() <= 2048 => {
                WebOriginCheck::Allowed
            }
            Some(_) => WebOriginCheck::Denied,
        })
    }
}

/// Result of checking a request origin against one client.
pub enum WebOriginCheck {
    /// The client is enabled and registered this exact origin.
    Allowed,
    /// The client exists but this origin is not allowed for it.
    Denied,
    /// No client with this identifier exists in the realm.
    UnknownClient,
}
