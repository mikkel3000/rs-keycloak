//! Realm role administration and user realm role mappings.

use std::collections::BTreeMap;

use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row};

use crate::user_admin::{USER_COLUMNS, UserRecord, user_row};
use crate::{Actor, Storage, StorageError, audit};

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
    /// Internal identifier of the owning client, or `None` for a realm role.
    pub client: Option<String>,
}

/// A role to create in a container.
pub struct NewRole<'a> {
    /// Role identifier.
    pub id: &'a str,
    /// Role name, unique in its container.
    pub name: &'a str,
    /// Optional description.
    pub description: Option<&'a str>,
    /// Roles the new role includes, by name in their containers.
    pub composites: &'a RoleNames,
}

/// Outcome of creating a role.
pub enum RoleCreation {
    /// The role was created.
    Created,
    /// A role with this name already exists in the realm.
    Exists,
    /// A requested composite names no role of the realm.
    CompositeNotFound,
}

/// Outcome of changing a role's composites.
pub enum CompositeChange {
    /// Every named role was added or removed.
    Changed,
    /// The parent role does not exist.
    RoleNotFound,
    /// A child's name and identifier did not match a role of the realm.
    ChildNotFound,
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

/// Who holds directly mapped roles.
#[derive(Clone, Copy)]
pub enum RoleHolder<'a> {
    /// A user, by identifier.
    User(&'a str),
    /// A group, by identifier; its members and its subgroups' members
    /// gain its roles.
    Group(&'a str),
}

impl RoleHolder<'_> {
    fn id(&self) -> &str {
        match self {
            Self::User(id) | Self::Group(id) => id,
        }
    }

    /// The holder's table, mapping table and mapping column.
    fn tables(&self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::User(_) => ("users", "user_role_grants", "user_id"),
            Self::Group(_) => ("groups", "group_role_grants", "group_id"),
        }
    }

    fn event(&self, grant: bool) -> &'static str {
        match (self, grant) {
            (Self::User(_), true) => "user_roles_granted",
            (Self::User(_), false) => "user_roles_revoked",
            (Self::Group(_), true) => "group_roles_granted",
            (Self::Group(_), false) => "group_roles_revoked",
        }
    }
}

/// Outcome of changing a holder's role mappings.
pub enum RoleMappingChange {
    /// Every named role was mapped or unmapped.
    Changed,
    /// The user or group does not exist.
    HolderNotFound,
    /// A role's name and identifier did not match a realm role.
    RoleNotFound,
}

const ROLE_COLUMNS: &str = "r.id, r.name, r.description, r.client_id, EXISTS (SELECT 1 FROM role_composites c WHERE c.realm_id = r.realm_id AND c.role_id = r.id) AS composite";

fn role_row(row: &PgRow) -> Result<RoleRecord, StorageError> {
    Ok(RoleRecord {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        composite: row.try_get("composite")?,
        client: row.try_get("client_id")?,
    })
}

/// Resolves `(id, name)` pairs to role identifiers in one container (the
/// realm when `client` is `None`), or `None` if any pair does not match.
async fn resolve_roles(
    connection: &mut PgConnection,
    realm_id: &str,
    client: Option<&str>,
    roles: &[(String, String)],
) -> Result<Option<Vec<String>>, StorageError> {
    let mut ids = Vec::with_capacity(roles.len());
    for (id, name) in roles {
        let found: Option<String> = sqlx::query_scalar(
            "SELECT id FROM roles WHERE realm_id = $1 AND id = $2 AND name = $3 AND client_id IS NOT DISTINCT FROM $4",
        )
        .bind(realm_id)
        .bind(id)
        .bind(name)
        .bind(client)
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
    /// Lists the roles of a container (the realm when `client` is `None`) by name.
    pub async fn roles(
        &self,
        realm_id: &str,
        client: Option<&str>,
    ) -> Result<Vec<RoleRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query(&format!(
            "SELECT {ROLE_COLUMNS} FROM roles r WHERE r.realm_id = $1 AND r.client_id IS NOT DISTINCT FROM $2 ORDER BY r.name"
        ))
        .bind(realm_id)
        .bind(client)
        .fetch_all(tx.connection())
        .await?;
        tx.commit().await?;
        rows.iter().map(role_row).collect()
    }

    /// Reads one role of a container by name.
    pub async fn role(
        &self,
        realm_id: &str,
        client: Option<&str>,
        name: &str,
    ) -> Result<Option<RoleRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let row = sqlx::query(&format!(
            "SELECT {ROLE_COLUMNS} FROM roles r WHERE r.realm_id = $1 AND r.name = $2 AND r.client_id IS NOT DISTINCT FROM $3"
        ))
        .bind(realm_id)
        .bind(name)
        .bind(client)
        .fetch_optional(tx.connection())
        .await?;
        tx.commit().await?;
        row.as_ref().map(role_row).transpose()
    }

    /// Lists the roles a role directly includes, from any container, or
    /// `None` if the role does not exist.
    pub async fn role_composites(
        &self,
        realm_id: &str,
        client: Option<&str>,
        name: &str,
    ) -> Result<Option<Vec<RoleRecord>>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let parent: Option<String> = sqlx::query_scalar(
            "SELECT id FROM roles WHERE realm_id = $1 AND name = $2 AND client_id IS NOT DISTINCT FROM $3",
        )
        .bind(realm_id)
        .bind(name)
        .bind(client)
        .fetch_optional(tx.connection())
        .await?;
        let Some(parent) = parent else {
            tx.commit().await?;
            return Ok(None);
        };
        let rows = sqlx::query(&format!(
            "SELECT {ROLE_COLUMNS} FROM roles r JOIN role_composites c ON c.realm_id = r.realm_id AND c.child_role_id = r.id WHERE c.realm_id = $1 AND c.role_id = $2 ORDER BY r.name, r.id"
        ))
        .bind(realm_id)
        .bind(&parent)
        .fetch_all(tx.connection())
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(role_row)
            .collect::<Result<_, _>>()
            .map(Some)
    }

    /// Adds or removes children of a container's role. Children may come
    /// from any container of the realm, and self-inclusion and cycles are
    /// allowed, as in the reference.
    #[allow(clippy::too_many_arguments)]
    pub async fn change_composites(
        &self,
        realm_id: &str,
        client: Option<&str>,
        name: &str,
        children: &[(String, String)],
        grant: bool,
        actor: &Actor,
    ) -> Result<CompositeChange, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let parent: Option<String> = sqlx::query_scalar(
            "SELECT id FROM roles WHERE realm_id = $1 AND name = $2 AND client_id IS NOT DISTINCT FROM $3 FOR UPDATE",
        )
        .bind(realm_id)
        .bind(name)
        .bind(client)
        .fetch_optional(&mut *conn)
        .await?;
        let Some(parent) = parent else {
            tx.commit().await?;
            return Ok(CompositeChange::RoleNotFound);
        };
        let mut ids = Vec::with_capacity(children.len());
        for (id, name) in children {
            let found: Option<String> = sqlx::query_scalar(
                "SELECT id FROM roles WHERE realm_id = $1 AND id = $2 AND name = $3",
            )
            .bind(realm_id)
            .bind(id)
            .bind(name)
            .fetch_optional(&mut *conn)
            .await?;
            match found {
                Some(found) => ids.push(found),
                None => {
                    tx.commit().await?;
                    return Ok(CompositeChange::ChildNotFound);
                }
            }
        }
        let statement = if grant {
            "INSERT INTO role_composites (realm_id, role_id, child_role_id) SELECT $1, $2, unnest($3::text[]) ON CONFLICT DO NOTHING"
        } else {
            "DELETE FROM role_composites WHERE realm_id = $1 AND role_id = $2 AND child_role_id = ANY($3)"
        };
        sqlx::query(statement)
            .bind(realm_id)
            .bind(&parent)
            .bind(&ids)
            .execute(&mut *conn)
            .await?;
        let event = if grant {
            "role_composites_added"
        } else {
            "role_composites_removed"
        };
        audit(conn, actor, event).await?;
        tx.commit().await?;
        Ok(CompositeChange::Changed)
    }

    /// Creates a role in a container unless the name is taken there.
    pub async fn create_role(
        &self,
        realm_id: &str,
        client: Option<&str>,
        role: &NewRole<'_>,
        actor: &Actor,
    ) -> Result<RoleCreation, StorageError> {
        let NewRole {
            id,
            name,
            description,
            composites,
        } = role;
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let created: Option<String> = sqlx::query_scalar("INSERT INTO roles (realm_id, id, name, description, client_id) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING RETURNING id")
            .bind(realm_id).bind(id).bind(name).bind(description).bind(client).fetch_optional(&mut *conn).await?;
        if created.is_none() {
            tx.commit().await?;
            return Ok(RoleCreation::Exists);
        }
        // Callers pass each name once per container.
        let requested =
            composites.realm.len() + composites.clients.values().map(Vec::len).sum::<usize>();
        // Names resolve in their container; a client is named by its public identifier.
        let children: Vec<String> = sqlx::query_scalar("SELECT r.id FROM roles r LEFT JOIN clients c ON c.realm_id = r.realm_id AND c.id = r.client_id WHERE r.realm_id = $1 AND ((r.client_id IS NULL AND r.name = ANY($2)) OR (c.client_id, r.name) IN (SELECT * FROM unnest($3::text[], $4::text[])))")
            .bind(realm_id)
            .bind(&composites.realm)
            .bind(composites.clients.iter().flat_map(|(client, names)| names.iter().map(move |_| client.as_str())).collect::<Vec<_>>())
            .bind(composites.clients.values().flatten().map(String::as_str).collect::<Vec<_>>())
            .fetch_all(&mut *conn).await?;
        if children.len() != requested {
            // Dropping the transaction rolls the new role back.
            return Ok(RoleCreation::CompositeNotFound);
        }
        sqlx::query("INSERT INTO role_composites (realm_id, role_id, child_role_id) SELECT $1, $2, unnest($3::text[]) ON CONFLICT DO NOTHING")
            .bind(realm_id).bind(id).bind(&children).execute(&mut *conn).await?;
        audit(conn, actor, "role_created").await?;
        tx.commit().await?;
        Ok(RoleCreation::Created)
    }

    /// Deletes a role of a container and its mappings; the default role is kept.
    pub async fn delete_role(
        &self,
        realm_id: &str,
        client: Option<&str>,
        name: &str,
        actor: &Actor,
    ) -> Result<RoleDeletion, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let role: Option<(String, bool)> = sqlx::query_as("SELECT r.id, r.id = m.default_role_id FROM roles r JOIN realms m ON m.id = r.realm_id WHERE r.realm_id = $1 AND r.name = $2 AND r.client_id IS NOT DISTINCT FROM $3 FOR UPDATE OF r")
            .bind(realm_id).bind(name).bind(client).fetch_optional(&mut *conn).await?;
        let result = match role {
            None => RoleDeletion::NotFound,
            Some((_, true)) => RoleDeletion::DefaultRole,
            Some((id, false)) => {
                sqlx::query("DELETE FROM roles WHERE realm_id = $1 AND id = $2")
                    .bind(realm_id)
                    .bind(&id)
                    .execute(&mut *conn)
                    .await?;
                audit(conn, actor, "role_deleted").await?;
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

    /// Lists a holder's directly mapped roles in one container (the realm
    /// when `client` is `None`), or `None` if the holder does not exist.
    pub async fn holder_roles(
        &self,
        realm_id: &str,
        client: Option<&str>,
        holder: RoleHolder<'_>,
    ) -> Result<Option<Vec<RoleRecord>>, StorageError> {
        let (table, grants, column) = holder.tables();
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let exists: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM {table} WHERE realm_id = $1 AND id = $2)"
        ))
        .bind(realm_id)
        .bind(holder.id())
        .fetch_one(&mut *conn)
        .await?;
        let roles = if exists {
            let rows = sqlx::query(&format!("SELECT {ROLE_COLUMNS} FROM roles r JOIN {grants} g ON g.realm_id = r.realm_id AND g.role_id = r.id WHERE r.realm_id = $1 AND g.{column} = $2 AND r.client_id IS NOT DISTINCT FROM $3 ORDER BY r.name"))
                .bind(realm_id).bind(holder.id()).bind(client).fetch_all(&mut *conn).await?;
            Some(rows.iter().map(role_row).collect::<Result<_, _>>()?)
        } else {
            None
        };
        tx.commit().await?;
        Ok(roles)
    }

    /// Maps or unmaps roles of one container for a holder; every
    /// `(id, name)` pair must name a role of that container.
    pub async fn change_holder_roles(
        &self,
        realm_id: &str,
        client: Option<&str>,
        holder: RoleHolder<'_>,
        roles: &[(String, String)],
        grant: bool,
        actor: &Actor,
    ) -> Result<RoleMappingChange, StorageError> {
        let (table, grants, column) = holder.tables();
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let exists: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM {table} WHERE realm_id = $1 AND id = $2 FOR UPDATE)"
        ))
        .bind(realm_id)
        .bind(holder.id())
        .fetch_one(&mut *conn)
        .await?;
        if !exists {
            tx.commit().await?;
            return Ok(RoleMappingChange::HolderNotFound);
        }
        let Some(role_ids) = resolve_roles(conn, realm_id, client, roles).await? else {
            tx.commit().await?;
            return Ok(RoleMappingChange::RoleNotFound);
        };
        let statement = if grant {
            format!(
                "INSERT INTO {grants} (realm_id, {column}, role_id) SELECT $1, $2, unnest($3::text[]) ON CONFLICT DO NOTHING"
            )
        } else {
            format!(
                "DELETE FROM {grants} WHERE realm_id = $1 AND {column} = $2 AND role_id = ANY($3)"
            )
        };
        sqlx::query(&statement)
            .bind(realm_id)
            .bind(holder.id())
            .bind(&role_ids)
            .execute(&mut *conn)
            .await?;
        audit(conn, actor, holder.event(grant)).await?;
        tx.commit().await?;
        Ok(RoleMappingChange::Changed)
    }
}

/// The `effective` CTE of role identifiers for user `$2` of realm `$1`:
/// direct grants, grants of the user's groups and their ancestors, and every
/// role reachable from those through composites.
const EFFECTIVE_ROLES: &str = "WITH RECURSIVE member_groups(id, parent_id, depth) AS (SELECT g.id, g.parent_id, 0 FROM groups g JOIN group_members m ON m.realm_id = g.realm_id AND m.group_id = g.id WHERE m.realm_id = $1 AND m.user_id = $2 UNION SELECT p.id, p.parent_id, d.depth + 1 FROM groups p JOIN member_groups d ON p.realm_id = $1 AND p.id = d.parent_id WHERE d.depth < 64), effective(id, depth) AS (SELECT role_id, 0 FROM user_role_grants WHERE realm_id = $1 AND user_id = $2 UNION SELECT g.role_id, 0 FROM group_role_grants g JOIN member_groups m ON g.realm_id = $1 AND g.group_id = m.id UNION SELECT c.child_role_id, e.depth + 1 FROM role_composites c JOIN effective e ON c.realm_id = $1 AND c.role_id = e.id WHERE e.depth < 32)";

/// Role names by container: realm roles, and client roles by client.
#[derive(Default)]
pub struct RoleNames {
    /// Realm role names, sorted.
    pub realm: Vec<String>,
    /// Client role names keyed by public client identifier, sorted.
    pub clients: BTreeMap<String, Vec<String>>,
}

impl RoleNames {
    /// Groups `(client identifier, role name)` rows, realm roles first.
    fn from_rows(rows: Vec<(Option<String>, String)>) -> Self {
        let mut roles = Self::default();
        for (client, name) in rows {
            match client {
                None => roles.realm.push(name),
                Some(client) => roles.clients.entry(client).or_default().push(name),
            }
        }
        roles
    }
}

impl Storage {
    /// Returns a user's effective role names: direct and group grants plus
    /// every role reachable through composites, without duplicates.
    pub async fn effective_roles(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<RoleNames, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let rows: Vec<(Option<String>, String)> = sqlx::query_as(&format!("{EFFECTIVE_ROLES} SELECT DISTINCT c.client_id, r.name FROM roles r JOIN effective e ON r.realm_id = $1 AND r.id = e.id LEFT JOIN clients c ON c.realm_id = r.realm_id AND c.id = r.client_id ORDER BY 1 NULLS FIRST, 2"))
            .bind(realm_id).bind(user_id).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        Ok(RoleNames::from_rows(rows))
    }

    /// Lists a user's effective roles in one container (the realm when
    /// `client` is `None`), or `None` if the user does not exist.
    pub async fn effective_role_records(
        &self,
        realm_id: &str,
        client: Option<&str>,
        user_id: &str,
    ) -> Result<Option<Vec<RoleRecord>>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id = $2)",
        )
        .bind(realm_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;
        let roles = if exists {
            let rows = sqlx::query(&format!("{EFFECTIVE_ROLES} SELECT DISTINCT {ROLE_COLUMNS} FROM roles r JOIN effective e ON r.realm_id = $1 AND r.id = e.id WHERE r.client_id IS NOT DISTINCT FROM $3 ORDER BY r.name"))
                .bind(realm_id).bind(user_id).bind(client).fetch_all(&mut *conn).await?;
            Some(rows.iter().map(role_row).collect::<Result<_, _>>()?)
        } else {
            None
        };
        tx.commit().await?;
        Ok(roles)
    }

    /// Returns the names of a holder's directly mapped roles.
    pub async fn holder_role_names(
        &self,
        realm_id: &str,
        holder: RoleHolder<'_>,
    ) -> Result<RoleNames, StorageError> {
        let (_, grants, column) = holder.tables();
        let mut tx = self.begin_request(false).await?;
        let rows: Vec<(Option<String>, String)> = sqlx::query_as(&format!("SELECT c.client_id, r.name FROM roles r JOIN {grants} g ON g.realm_id = r.realm_id AND g.role_id = r.id LEFT JOIN clients c ON c.realm_id = r.realm_id AND c.id = r.client_id WHERE r.realm_id = $1 AND g.{column} = $2 ORDER BY 1 NULLS FIRST, 2"))
            .bind(realm_id).bind(holder.id()).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        Ok(RoleNames::from_rows(rows))
    }
}
