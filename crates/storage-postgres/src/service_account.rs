//! Service-account users owned by confidential clients.

use sqlx::{PgConnection, Row};

use crate::{AccessTokenStatus, Storage, StorageError, authenticated_client};

/// The user a client acts as in the client-credentials grant.
pub struct ServiceAccount {
    /// User identifier, used as the token subject.
    pub user_id: String,
    /// Username, `service-account-` followed by the lowercased client ID.
    pub username: String,
}

/// Outcome of resolving a client's service account for a grant.
pub enum ServiceAccountGrant {
    /// The client may act as this enabled user.
    Granted(ServiceAccount),
    /// The client has not enabled service accounts.
    NotEnabled,
    /// Service accounts are enabled but the account user is missing.
    MissingUser,
    /// The account user exists but is disabled; carries its username.
    UserDisabled(String),
}

/// Keycloak's service-account username for a client identifier.
pub fn service_account_username(client_identifier: &str) -> String {
    format!("service-account-{}", client_identifier.to_lowercase())
}

impl Storage {
    /// Enables service accounts for an enabled confidential client and creates
    /// its account user once; repeating the call changes nothing.
    ///
    /// Returns false if the client is missing, disabled, or public. A different
    /// user that already holds the account username is a `Conflict`.
    pub async fn enable_service_account(
        &self,
        realm: &str,
        client_identifier: &str,
        user_id: &str,
    ) -> Result<bool, StorageError> {
        let username = service_account_username(client_identifier);
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let client: Option<String> = sqlx::query_scalar("UPDATE clients c SET service_accounts_enabled = true FROM realms r WHERE r.id = c.realm_id AND c.realm_id = $1 AND c.client_id = $2 AND c.enabled AND r.enabled AND NOT c.public_client RETURNING c.id")
            .bind(realm).bind(client_identifier).fetch_optional(&mut *conn).await?;
        let Some(client) = client else {
            tx.commit().await?;
            return Ok(false);
        };
        let existing: Option<Option<String>> = sqlx::query_scalar("SELECT service_account_client_id FROM users WHERE realm_id = $1 AND username_normalized = $2 FOR UPDATE")
            .bind(realm).bind(&username).fetch_optional(&mut *conn).await?;
        match existing {
            Some(Some(owner)) if owner == client => (),
            Some(_) => return Err(StorageError::Conflict),
            None => {
                sqlx::query("INSERT INTO users (realm_id, id, username, username_normalized, service_account_client_id) VALUES ($1, $2, $3, $3, $4)")
                    .bind(realm).bind(user_id).bind(&username).bind(&client).execute(&mut *conn).await?;
            }
        }
        tx.commit().await?;
        Ok(true)
    }

    /// Resolves the service account of an authenticated confidential client,
    /// rechecking the client revision observed during authentication.
    pub async fn service_account_grant(
        &self,
        realm: &str,
        client_identifier: &str,
        client_revision: i64,
    ) -> Result<ServiceAccountGrant, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let client = authenticated_client(
            tx.connection(),
            realm,
            client_identifier,
            Some(client_revision),
        )
        .await?;
        let enabled: bool = sqlx::query_scalar(
            "SELECT service_accounts_enabled FROM clients WHERE realm_id = $1 AND id = $2",
        )
        .bind(realm)
        .bind(&client)
        .fetch_one(tx.connection())
        .await?;
        let result = if !enabled {
            ServiceAccountGrant::NotEnabled
        } else {
            let row = sqlx::query("SELECT id, username, enabled FROM users WHERE realm_id = $1 AND service_account_client_id = $2")
                .bind(realm).bind(&client).fetch_optional(tx.connection()).await?;
            match row {
                None => ServiceAccountGrant::MissingUser,
                Some(row) if !row.try_get::<bool, _>("enabled")? => {
                    ServiceAccountGrant::UserDisabled(row.try_get("username")?)
                }
                Some(row) => ServiceAccountGrant::Granted(ServiceAccount {
                    user_id: row.try_get("id")?,
                    username: row.try_get("username")?,
                }),
            }
        };
        tx.commit().await?;
        Ok(result)
    }
}

/// Checks a sessionless token against its client's current service account.
pub(crate) async fn lookup_service_account_token(
    connection: &mut PgConnection,
    realm: &str,
    client_identifier: &str,
    user_id: &str,
) -> Result<AccessTokenStatus, StorageError> {
    let row = sqlx::query("SELECT u.id, u.username FROM users u JOIN clients c ON c.realm_id = u.realm_id AND c.id = u.service_account_client_id JOIN realms r ON r.id = u.realm_id WHERE u.realm_id = $1 AND c.client_id = $2 AND u.id = $3 AND u.enabled AND c.enabled AND c.service_accounts_enabled AND r.enabled")
        .bind(realm).bind(client_identifier).bind(user_id).fetch_optional(connection).await?;
    Ok(match row {
        Some(row) => AccessTokenStatus::ServiceAccount(ServiceAccount {
            user_id: row.try_get("id")?,
            username: row.try_get("username")?,
        }),
        None => AccessTokenStatus::SessionNotFound,
    })
}
