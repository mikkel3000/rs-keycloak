//! Realm role administration and user realm role mappings.

use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row};

use crate::realm_admin::MASTER_REALM;
use crate::user_admin::{USER_COLUMNS, UserRecord, user_row};
use crate::{Storage, StorageError};

/// A realm role with the fields of the admin representation.
pub struct RoleRecord {
    /// Role identifier.
    pub id: String,
    /// Role name, unique in the realm.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Whether the role includes other roles.
    pub composite: bool,
}

/// Outcome of creating a role.
pub enum RoleCreation {
    /// The role was created.
    Created,
    /// A role with this name already exists in the realm.
    Exists,
}

/// Outcome of deleting a role.
pub enum RoleDeletion {
    /// The role and its mappings were removed.
    Deleted,
    /// No role with this name exists.
    NotFound,
    /// The realm's default role cannot be removed.
    DefaultRole,
}

/// Outcome of changing a user's realm role mappings.
pub enum RoleMappingChange {
    /// Every named role was mapped or unmapped.
    Changed,
    /// The user does not exist.
    UserNotFound,
    /// A role's name and identifier did not match a realm role.
    RoleNotFound,
}

const ROLE_COLUMNS: &str = "r.id, r.name, r.description, EXISTS (SELECT 1 FROM role_composites c WHERE c.realm_id = r.realm_id AND c.role_id = r.id) AS composite";

fn role_row(row: &PgRow) -> Result<RoleRecord, StorageError> {
    Ok(RoleRecord {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        composite: row.try_get("composite")?,
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

/// Resolves `(id, name)` pairs to realm role identifiers, or `None` if any
/// pair does not name the same role.
async fn resolve_roles(
    connection: &mut PgConnection,
    realm_id: &str,
    roles: &[(String, String)],
) -> Result<Option<Vec<String>>, StorageError> {
    let mut ids = Vec::with_capacity(roles.len());
    for (id, name) in roles {
        let found: Option<String> = sqlx::query_scalar(
            "SELECT id FROM roles WHERE realm_id = $1 AND id = $2 AND name = $3",
        )
        .bind(realm_id)
        .bind(id)
        .bind(name)
        .fetch_optional(&mut *connection)
        .await?;
        match found {
            Some(found) => ids.push(found),
            None => return Ok(None),
        }
    }
    Ok(Some(ids))
}

impl Storage {
    /// Lists the realm's roles by name.
    pub async fn roles(&self, realm_id: &str) -> Result<Vec<RoleRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query(&format!(
            "SELECT {ROLE_COLUMNS} FROM roles r WHERE r.realm_id = $1 ORDER BY r.name"
        ))
        .bind(realm_id)
        .fetch_all(tx.connection())
        .await?;
        tx.commit().await?;
        rows.iter().map(role_row).collect()
    }

    /// Reads one role by name.
    pub async fn role(
        &self,
        realm_id: &str,
        name: &str,
    ) -> Result<Option<RoleRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let row = sqlx::query(&format!(
            "SELECT {ROLE_COLUMNS} FROM roles r WHERE r.realm_id = $1 AND r.name = $2"
        ))
        .bind(realm_id)
        .bind(name)
        .fetch_optional(tx.connection())
        .await?;
        tx.commit().await?;
        row.as_ref().map(role_row).transpose()
    }

    /// Creates a role unless the name is taken.
    pub async fn create_role(
        &self,
        realm_id: &str,
        id: &str,
        name: &str,
        description: Option<&str>,
        actor_user_id: &str,
    ) -> Result<RoleCreation, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let created: Option<String> = sqlx::query_scalar("INSERT INTO roles (realm_id, id, name, description) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING RETURNING id")
            .bind(realm_id).bind(id).bind(name).bind(description).fetch_optional(&mut *conn).await?;
        if created.is_none() {
            tx.commit().await?;
            return Ok(RoleCreation::Exists);
        }
        audit(conn, actor_user_id, "role_created").await?;
        tx.commit().await?;
        Ok(RoleCreation::Created)
    }

    /// Deletes a role and its mappings; the default role is kept.
    pub async fn delete_role(
        &self,
        realm_id: &str,
        name: &str,
        actor_user_id: &str,
    ) -> Result<RoleDeletion, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let role: Option<(String, bool)> = sqlx::query_as("SELECT r.id, r.id = m.default_role_id FROM roles r JOIN realms m ON m.id = r.realm_id WHERE r.realm_id = $1 AND r.name = $2 FOR UPDATE OF r")
            .bind(realm_id).bind(name).fetch_optional(&mut *conn).await?;
        let result = match role {
            None => RoleDeletion::NotFound,
            Some((_, true)) => RoleDeletion::DefaultRole,
            Some((id, false)) => {
                sqlx::query("DELETE FROM roles WHERE realm_id = $1 AND id = $2")
                    .bind(realm_id)
                    .bind(&id)
                    .execute(&mut *conn)
                    .await?;
                audit(conn, actor_user_id, "role_deleted").await?;
                RoleDeletion::Deleted
            }
        };
        tx.commit().await?;
        Ok(result)
    }

    /// Lists users directly holding a role, by username.
    pub async fn role_users(
        &self,
        realm_id: &str,
        role_id: &str,
    ) -> Result<Vec<UserRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query(&format!("SELECT {USER_COLUMNS} FROM users WHERE realm_id = $1 AND id IN (SELECT user_id FROM user_role_grants WHERE realm_id = $1 AND role_id = $2) ORDER BY username_normalized"))
            .bind(realm_id).bind(role_id).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter().map(user_row).collect()
    }

    /// Lists the roles mapped directly to a user, or `None` if the user is missing.
    pub async fn user_roles(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Option<Vec<RoleRecord>>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id = $2)",
        )
        .bind(realm_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;
        let roles = if exists {
            let rows = sqlx::query(&format!("SELECT {ROLE_COLUMNS} FROM roles r JOIN user_role_grants g ON g.realm_id = r.realm_id AND g.role_id = r.id WHERE r.realm_id = $1 AND g.user_id = $2 ORDER BY r.name"))
                .bind(realm_id).bind(user_id).fetch_all(&mut *conn).await?;
            Some(rows.iter().map(role_row).collect::<Result<_, _>>()?)
        } else {
            None
        };
        tx.commit().await?;
        Ok(roles)
    }

    /// Maps or unmaps realm roles for a user; all roles must resolve first.
    pub async fn change_user_roles(
        &self,
        realm_id: &str,
        user_id: &str,
        roles: &[(String, String)],
        grant: bool,
        actor_user_id: &str,
    ) -> Result<RoleMappingChange, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id = $2 FOR UPDATE)",
        )
        .bind(realm_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;
        if !exists {
            tx.commit().await?;
            return Ok(RoleMappingChange::UserNotFound);
        }
        let Some(role_ids) = resolve_roles(conn, realm_id, roles).await? else {
            tx.commit().await?;
            return Ok(RoleMappingChange::RoleNotFound);
        };
        let statement = if grant {
            "INSERT INTO user_role_grants (realm_id, user_id, role_id) SELECT $1, $2, unnest($3::text[]) ON CONFLICT DO NOTHING"
        } else {
            "DELETE FROM user_role_grants WHERE realm_id = $1 AND user_id = $2 AND role_id = ANY($3)"
        };
        sqlx::query(statement)
            .bind(realm_id)
            .bind(user_id)
            .bind(&role_ids)
            .execute(&mut *conn)
            .await?;
        audit(
            conn,
            actor_user_id,
            if grant {
                "user_roles_granted"
            } else {
                "user_roles_revoked"
            },
        )
        .await?;
        tx.commit().await?;
        Ok(RoleMappingChange::Changed)
    }
}
