//! Client administration within a realm, audited in the master realm.

use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row};

use crate::realm_admin::MASTER_REALM;
use crate::service_account::service_account_username;
use crate::{Storage, StorageError};

/// A client secret sealed with the operator key for one client row.
pub struct SealedSecret {
    /// Nonce and AES-256-GCM ciphertext.
    pub sealed: Vec<u8>,
    /// Identifier of the sealing key.
    pub key_id: String,
}

/// Settings for a new client; callers validate URLs and origins first.
pub struct NewClient<'a> {
    /// Public client identifier.
    pub client_identifier: &'a str,
    /// Whether the client may be used.
    pub enabled: bool,
    /// Whether the client authenticates without a secret.
    pub public: bool,
    /// Whether the browser authorization-code flow is allowed.
    pub standard_flow: bool,
    /// Whether the client-credentials grant is allowed.
    pub service_accounts: bool,
    /// Whether the client only verifies tokens and never obtains them.
    pub bearer_only: bool,
    /// Exact redirect URIs.
    pub redirect_uris: &'a [String],
    /// Exact web origins.
    pub web_origins: &'a [String],
    /// Exact post-logout redirect URIs.
    pub post_logout_redirect_uris: &'a [String],
    /// Whether every redirect URI is also a post-logout redirect URI.
    pub post_logout_uses_redirect_uris: bool,
    /// Whether users must consent before the client receives a code.
    pub consent_required: bool,
}

/// A stored client with the fields of the admin representation.
pub struct ClientRecord {
    /// Internal identifier, used in admin URLs.
    pub id: String,
    /// Public client identifier.
    pub client_identifier: String,
    /// Whether the client may be used.
    pub enabled: bool,
    /// Whether the client authenticates without a secret.
    pub public: bool,
    /// Whether the browser authorization-code flow is allowed.
    pub standard_flow: bool,
    /// Whether the client-credentials grant is allowed.
    pub service_accounts: bool,
    /// Whether the client only verifies tokens and never obtains them.
    pub bearer_only: bool,
    /// Whether users must consent before the client receives a code.
    pub consent_required: bool,
    /// Exact redirect URIs, sorted.
    pub redirect_uris: Vec<String>,
    /// Exact web origins, sorted.
    pub web_origins: Vec<String>,
    /// Recoverable secret, if the client has one; hashed secrets are absent.
    pub secret: Option<SealedSecret>,
}

/// Outcome of creating a client.
pub enum ClientCreation {
    /// The client was created.
    Created,
    /// A client with this identifier already exists in the realm.
    Exists,
}

const CLIENT_COLUMNS: &str = "c.id, c.client_id, c.enabled, c.public_client, c.standard_flow_enabled, c.service_accounts_enabled, c.bearer_only, c.consent_required, c.secret_sealed, c.secret_key_id, ARRAY(SELECT d.redirect_uri FROM client_redirect_uris d WHERE d.realm_id = c.realm_id AND d.client_id = c.id ORDER BY d.redirect_uri) AS redirect_uris, ARRAY(SELECT o.origin FROM client_web_origins o WHERE o.realm_id = c.realm_id AND o.client_id = c.id ORDER BY o.origin) AS web_origins";

fn client_row(row: &PgRow) -> Result<ClientRecord, StorageError> {
    let sealed: Option<Vec<u8>> = row.try_get("secret_sealed")?;
    let key_id: Option<String> = row.try_get("secret_key_id")?;
    Ok(ClientRecord {
        id: row.try_get("id")?,
        client_identifier: row.try_get("client_id")?,
        enabled: row.try_get("enabled")?,
        public: row.try_get("public_client")?,
        standard_flow: row.try_get("standard_flow_enabled")?,
        service_accounts: row.try_get("service_accounts_enabled")?,
        bearer_only: row.try_get("bearer_only")?,
        consent_required: row.try_get("consent_required")?,
        redirect_uris: row.try_get("redirect_uris")?,
        web_origins: row.try_get("web_origins")?,
        secret: sealed
            .zip(key_id)
            .map(|(sealed, key_id)| SealedSecret { sealed, key_id }),
    })
}

async fn audit(
    connection: &mut PgConnection,
    actor: &str,
    event: &str,
) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT INTO audit_events (realm_id, actor_user_id, event_type) VALUES ($1, $2, $3)",
    )
    .bind(MASTER_REALM)
    .bind(actor)
    .bind(event)
    .execute(connection)
    .await?;
    Ok(())
}

impl Storage {
    /// Creates a client with its redirects, origins and, if enabled, its
    /// service-account user. Confidential clients must supply a sealed secret.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_client(
        &self,
        realm_id: &str,
        id: &str,
        client: &NewClient<'_>,
        secret: Option<&SealedSecret>,
        service_account_user_id: &str,
        actor_user_id: &str,
    ) -> Result<ClientCreation, StorageError> {
        if client.public == secret.is_some() || (client.public && client.service_accounts) {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let created: Option<String> = sqlx::query_scalar("INSERT INTO clients (realm_id, id, client_id, enabled, public_client, standard_flow_enabled, service_accounts_enabled, secret_sealed, secret_key_id, post_logout_uses_redirect_uris, consent_required, bearer_only) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT DO NOTHING RETURNING id")
            .bind(realm_id).bind(id).bind(client.client_identifier).bind(client.enabled).bind(client.public)
            .bind(client.standard_flow).bind(client.service_accounts)
            .bind(secret.map(|secret| secret.sealed.as_slice())).bind(secret.map(|secret| secret.key_id.as_str()))
            .bind(client.post_logout_uses_redirect_uris)
            .bind(client.consent_required)
            .bind(client.bearer_only)
            .fetch_optional(&mut *conn).await?;
        if created.is_none() {
            tx.commit().await?;
            return Ok(ClientCreation::Exists);
        }
        for uri in client.redirect_uris {
            sqlx::query("INSERT INTO client_redirect_uris (realm_id, client_id, redirect_uri) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                .bind(realm_id).bind(id).bind(uri).execute(&mut *conn).await?;
        }
        for uri in client.post_logout_redirect_uris {
            sqlx::query("INSERT INTO client_post_logout_redirect_uris (realm_id, client_id, redirect_uri) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                .bind(realm_id).bind(id).bind(uri).execute(&mut *conn).await?;
        }
        for origin in client.web_origins {
            sqlx::query("INSERT INTO client_web_origins (realm_id, client_id, origin) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                .bind(realm_id).bind(id).bind(origin).execute(&mut *conn).await?;
        }
        if client.service_accounts {
            let username = service_account_username(client.client_identifier);
            let inserted = sqlx::query("INSERT INTO users (realm_id, id, username, username_normalized, service_account_client_id, enabled) VALUES ($1, $2, $3, $3, $4, true) ON CONFLICT DO NOTHING")
                .bind(realm_id).bind(service_account_user_id).bind(&username).bind(id)
                .execute(&mut *conn).await?.rows_affected();
            if inserted == 0 {
                return Err(StorageError::Conflict);
            }
        }
        audit(conn, actor_user_id, "client_created").await?;
        tx.commit().await?;
        Ok(ClientCreation::Created)
    }

    /// Reads one client by internal identifier.
    pub async fn client(
        &self,
        realm_id: &str,
        id: &str,
    ) -> Result<Option<ClientRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let row = sqlx::query(&format!(
            "SELECT {CLIENT_COLUMNS} FROM clients c WHERE c.realm_id = $1 AND c.id = $2"
        ))
        .bind(realm_id)
        .bind(id)
        .fetch_optional(tx.connection())
        .await?;
        tx.commit().await?;
        row.as_ref().map(client_row).transpose()
    }

    /// Lists the realm's clients by identifier, optionally one exact identifier.
    pub async fn clients(
        &self,
        realm_id: &str,
        client_identifier: Option<&str>,
    ) -> Result<Vec<ClientRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query(&format!("SELECT {CLIENT_COLUMNS} FROM clients c WHERE c.realm_id = $1 AND ($2::text IS NULL OR c.client_id = $2) ORDER BY c.client_id"))
            .bind(realm_id)
            .bind(client_identifier)
            .fetch_all(tx.connection())
            .await?;
        tx.commit().await?;
        rows.iter().map(client_row).collect()
    }

    /// Replaces a confidential client's secret with a new sealed one; the
    /// revision bump makes in-flight authentications with the old secret fail.
    pub async fn replace_client_secret(
        &self,
        realm_id: &str,
        id: &str,
        secret: &SealedSecret,
        actor_user_id: &str,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let changed = sqlx::query("UPDATE clients SET secret_phc = NULL, secret_sealed = $3, secret_key_id = $4 WHERE realm_id = $1 AND id = $2 AND NOT public_client")
            .bind(realm_id).bind(id).bind(&secret.sealed).bind(&secret.key_id)
            .execute(&mut *conn).await?.rows_affected();
        if changed == 0 {
            tx.commit().await?;
            return Ok(false);
        }
        audit(conn, actor_user_id, "client_secret_regenerated").await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Returns the user identifier of a client's service account, if any.
    pub async fn service_account_user_id(
        &self,
        realm_id: &str,
        id: &str,
    ) -> Result<Option<String>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let user = sqlx::query_scalar("SELECT u.id FROM users u JOIN clients c ON c.realm_id = u.realm_id AND c.id = u.service_account_client_id WHERE u.realm_id = $1 AND c.id = $2 AND c.service_accounts_enabled")
            .bind(realm_id).bind(id).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        Ok(user)
    }

    /// Deletes a client with its redirects, origins, sessions and service
    /// account; returns false if it does not exist.
    pub async fn delete_client(
        &self,
        realm_id: &str,
        id: &str,
        actor_user_id: &str,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let deleted = sqlx::query("DELETE FROM clients WHERE realm_id = $1 AND id = $2")
            .bind(realm_id)
            .bind(id)
            .execute(&mut *conn)
            .await?
            .rows_affected();
        if deleted == 0 {
            tx.commit().await?;
            return Ok(false);
        }
        audit(conn, actor_user_id, "client_deleted").await?;
        tx.commit().await?;
        Ok(true)
    }
}
