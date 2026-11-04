//! Realm administration and master-realm administrator checks.

use sqlx::Row;

use crate::{Storage, StorageError};

/// The administrative realm; it cannot be deleted.
pub const MASTER_REALM: &str = "master";

/// A realm as stored, including disabled realms.
pub struct RealmRecord {
    /// Stable realm identifier.
    pub id: String,
    /// Realm name used in URLs.
    pub name: String,
    /// Whether the realm serves authentication.
    pub enabled: bool,
}

/// Outcome of creating a realm.
pub enum RealmCreation {
    /// The realm was created.
    Created,
    /// A realm with this name already exists.
    Exists,
}

/// Outcome of deleting a realm.
pub enum RealmDeletion {
    /// The realm and all of its data were removed.
    Deleted,
    /// No realm with this name exists.
    NotFound,
    /// The master realm cannot be removed.
    Master,
}

impl Storage {
    /// Reports whether a master-realm user holds the master `admin` role.
    pub async fn is_master_admin(&self, user_id: &str) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let admin = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_role_grants g JOIN roles r ON r.realm_id = g.realm_id AND r.id = g.role_id JOIN users u ON u.realm_id = g.realm_id AND u.id = g.user_id WHERE g.realm_id = $1 AND g.user_id = $2 AND r.name = 'admin' AND u.enabled)")
            .bind(MASTER_REALM).bind(user_id).fetch_one(tx.connection()).await?;
        tx.commit().await?;
        Ok(admin)
    }

    /// Grants the master `admin` role to a master client's service account.
    ///
    /// Returns false if the client or its service account does not exist.
    pub async fn grant_master_admin(&self, client_identifier: &str) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let granted = sqlx::query("INSERT INTO user_role_grants (realm_id, user_id, role_id) SELECT u.realm_id, u.id, r.id FROM users u JOIN clients c ON c.realm_id = u.realm_id AND c.id = u.service_account_client_id JOIN roles r ON r.realm_id = u.realm_id AND r.name = 'admin' WHERE u.realm_id = $1 AND c.client_id = $2 AND c.service_accounts_enabled ON CONFLICT DO NOTHING RETURNING user_id")
            .bind(MASTER_REALM).bind(client_identifier).fetch_optional(tx.connection()).await?;
        let exists = match granted {
            Some(_) => true,
            None => sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users u JOIN clients c ON c.realm_id = u.realm_id AND c.id = u.service_account_client_id WHERE u.realm_id = $1 AND c.client_id = $2 AND c.service_accounts_enabled)")
                .bind(MASTER_REALM).bind(client_identifier).fetch_one(tx.connection()).await?,
        };
        tx.commit().await?;
        Ok(exists)
    }

    /// Looks up a realm by name whether or not it is enabled.
    pub async fn realm_by_name(&self, name: &str) -> Result<Option<RealmRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let row = sqlx::query("SELECT id, name, enabled FROM realms WHERE name = $1")
            .bind(name)
            .fetch_optional(tx.connection())
            .await?;
        tx.commit().await?;
        row.map(|row| {
            Ok(RealmRecord {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                enabled: row.try_get("enabled")?,
            })
        })
        .transpose()
    }

    /// Creates a realm and records the action in the master audit log.
    pub async fn create_realm(
        &self,
        realm_id: &str,
        name: &str,
        enabled: bool,
        actor_user_id: &str,
    ) -> Result<RealmCreation, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let created: Option<String> = sqlx::query_scalar("INSERT INTO realms (id, name, enabled) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING RETURNING id")
            .bind(realm_id).bind(name).bind(enabled).fetch_optional(tx.connection()).await?;
        if created.is_none() {
            tx.commit().await?;
            return Ok(RealmCreation::Exists);
        }
        sqlx::query("INSERT INTO audit_events (realm_id, actor_user_id, event_type) VALUES ($1, $2, 'realm_created')")
            .bind(MASTER_REALM).bind(actor_user_id).execute(tx.connection()).await?;
        tx.commit().await?;
        Ok(RealmCreation::Created)
    }

    /// Deletes a realm and its data, recording the action in the master audit log.
    pub async fn delete_realm(
        &self,
        name: &str,
        actor_user_id: &str,
    ) -> Result<RealmDeletion, StorageError> {
        if name == MASTER_REALM {
            return Ok(RealmDeletion::Master);
        }
        let mut tx = self.begin_request(false).await?;
        let deleted = sqlx::query("DELETE FROM realms WHERE name = $1 AND id <> $2")
            .bind(name)
            .bind(MASTER_REALM)
            .execute(tx.connection())
            .await?
            .rows_affected();
        if deleted == 0 {
            tx.commit().await?;
            return Ok(RealmDeletion::NotFound);
        }
        sqlx::query("INSERT INTO audit_events (realm_id, actor_user_id, event_type) VALUES ($1, $2, 'realm_deleted')")
            .bind(MASTER_REALM).bind(actor_user_id).execute(tx.connection()).await?;
        tx.commit().await?;
        Ok(RealmDeletion::Deleted)
    }
}
