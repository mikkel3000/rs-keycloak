//! Realm administration and master-realm administrator checks.

use sqlx::Row;
use sqlx::postgres::PgRow;

use crate::{Actor, Storage, StorageError, audit};

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
    /// SMTP settings, if the realm has a mail server.
    pub smtp: Option<RealmSmtp>,
    /// Whether the login page offers forgot-password.
    pub reset_password_allowed: bool,
    /// Whether users must verify their email at login.
    pub verify_email: bool,
}

/// Settings for a new realm.
pub struct RealmSettings {
    /// Whether the realm serves authentication.
    pub enabled: bool,
    /// Whether the login page offers forgot-password.
    pub reset_password_allowed: bool,
    /// Whether users must verify their email at login.
    pub verify_email: bool,
    /// SMTP settings, if any.
    pub smtp: Option<RealmSmtp>,
}

/// A realm's SMTP settings as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmSmtp {
    /// Server host.
    pub host: String,
    /// Server port.
    pub port: i32,
    /// Sender address, if set.
    pub from: Option<String>,
    /// Sender display name, if set.
    pub from_display_name: Option<String>,
    /// Upgrade with STARTTLS.
    pub starttls: bool,
    /// Connect with implicit TLS.
    pub ssl: bool,
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

const REALM_COLUMNS: &str = "id, name, enabled, reset_password_allowed, verify_email, smtp_host, smtp_port, smtp_from, smtp_from_display_name, smtp_starttls, smtp_ssl";

fn realm_row(row: &PgRow) -> Result<RealmRecord, StorageError> {
    let host: Option<String> = row.try_get("smtp_host")?;
    let port: Option<i32> = row.try_get("smtp_port")?;
    Ok(RealmRecord {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        enabled: row.try_get("enabled")?,
        reset_password_allowed: row.try_get("reset_password_allowed")?,
        verify_email: row.try_get("verify_email")?,
        smtp: match host.zip(port) {
            Some((host, port)) => Some(RealmSmtp {
                host,
                port,
                from: row.try_get("smtp_from")?,
                from_display_name: row.try_get("smtp_from_display_name")?,
                starttls: row.try_get("smtp_starttls")?,
                ssl: row.try_get("smtp_ssl")?,
            }),
            None => None,
        },
    })
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
        let row = sqlx::query(&format!(
            "SELECT {REALM_COLUMNS} FROM realms WHERE name = $1"
        ))
        .bind(name)
        .fetch_optional(tx.connection())
        .await?;
        tx.commit().await?;
        row.as_ref().map(realm_row).transpose()
    }

    /// Lists every realm by name.
    pub async fn realms(&self) -> Result<Vec<RealmRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query(&format!("SELECT {REALM_COLUMNS} FROM realms ORDER BY name"))
            .fetch_all(tx.connection())
            .await?;
        tx.commit().await?;
        rows.iter().map(realm_row).collect()
    }

    /// Creates a realm and records the action in the master audit log.
    pub async fn create_realm(
        &self,
        realm_id: &str,
        name: &str,
        settings: &RealmSettings,
        actor: &Actor,
    ) -> Result<RealmCreation, StorageError> {
        let smtp = settings.smtp.as_ref();
        let mut tx = self.begin_request(false).await?;
        let created: Option<String> = sqlx::query_scalar("INSERT INTO realms (id, name, enabled, smtp_host, smtp_port, smtp_from, smtp_from_display_name, smtp_starttls, smtp_ssl, reset_password_allowed, verify_email) VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, false), COALESCE($9, false), $10, $11) ON CONFLICT DO NOTHING RETURNING id")
            .bind(realm_id).bind(name).bind(settings.enabled)
            .bind(smtp.map(|smtp| smtp.host.as_str())).bind(smtp.map(|smtp| smtp.port))
            .bind(smtp.and_then(|smtp| smtp.from.as_deref())).bind(smtp.and_then(|smtp| smtp.from_display_name.as_deref()))
            .bind(smtp.map(|smtp| smtp.starttls)).bind(smtp.map(|smtp| smtp.ssl)).bind(settings.reset_password_allowed).bind(settings.verify_email)
            .fetch_optional(tx.connection()).await?;
        if created.is_none() {
            tx.commit().await?;
            return Ok(RealmCreation::Exists);
        }
        audit(tx.connection(), actor, "realm_created").await?;
        tx.commit().await?;
        Ok(RealmCreation::Created)
    }

    /// Updates a realm's enabled flag and, when given, its SMTP settings
    /// (`Some(None)` removes them); returns false if the realm is missing.
    pub async fn update_realm(
        &self,
        name: &str,
        enabled: Option<bool>,
        reset_password_allowed: Option<bool>,
        verify_email: Option<bool>,
        smtp: Option<Option<&RealmSmtp>>,
        actor: &Actor,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let replace = smtp.is_some();
        let smtp = smtp.flatten();
        let changed = sqlx::query("UPDATE realms SET enabled = COALESCE($2, enabled), reset_password_allowed = COALESCE($10, reset_password_allowed), verify_email = COALESCE($11, verify_email), smtp_host = CASE WHEN $3 THEN $4 ELSE smtp_host END, smtp_port = CASE WHEN $3 THEN $5 ELSE smtp_port END, smtp_from = CASE WHEN $3 THEN $6 ELSE smtp_from END, smtp_from_display_name = CASE WHEN $3 THEN $7 ELSE smtp_from_display_name END, smtp_starttls = CASE WHEN $3 THEN COALESCE($8, false) ELSE smtp_starttls END, smtp_ssl = CASE WHEN $3 THEN COALESCE($9, false) ELSE smtp_ssl END WHERE name = $1")
            .bind(name).bind(enabled).bind(replace)
            .bind(smtp.map(|smtp| smtp.host.as_str())).bind(smtp.map(|smtp| smtp.port))
            .bind(smtp.and_then(|smtp| smtp.from.as_deref())).bind(smtp.and_then(|smtp| smtp.from_display_name.as_deref()))
            .bind(smtp.map(|smtp| smtp.starttls)).bind(smtp.map(|smtp| smtp.ssl)).bind(reset_password_allowed).bind(verify_email)
            .execute(&mut *conn).await?.rows_affected();
        if changed == 0 {
            tx.commit().await?;
            return Ok(false);
        }
        audit(&mut *conn, actor, "realm_updated").await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Deletes a realm and its data, recording the action in the master audit log.
    pub async fn delete_realm(
        &self,
        name: &str,
        actor: &Actor,
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
        audit(tx.connection(), actor, "realm_deleted").await?;
        tx.commit().await?;
        Ok(RealmDeletion::Deleted)
    }
}
