//! Group administration and user group membership.

use sqlx::Row;
use sqlx::postgres::PgRow;

use crate::user_admin::{USER_COLUMNS, UserRecord, user_row};
use crate::{Actor, Storage, StorageError, audit};

/// A group with the fields of the admin representation.
pub struct GroupRecord {
    /// Group identifier.
    pub id: String,
    /// Group name, unique among its siblings.
    pub name: String,
    /// Parent group, absent for top-level groups.
    pub parent_id: Option<String>,
    /// Slash-joined names from the root.
    pub path: String,
    /// Number of direct subgroups.
    pub sub_group_count: i64,
}

/// Outcome of creating a group.
pub enum GroupCreation {
    /// The group was created.
    Created(GroupRecord),
    /// A sibling (or top-level group) already has this name.
    Exists,
    /// The parent group does not exist.
    ParentNotFound,
}

/// Outcome of renaming or moving a group.
pub enum GroupChange {
    /// The group now has the requested name or parent.
    Changed,
    /// The group does not exist.
    NotFound,
    /// The new parent does not exist.
    ParentNotFound,
    /// A sibling at the destination already has the group's name.
    Exists,
    /// The new parent is one of the group's own subgroups.
    Cycle,
}

/// Outcome of changing a user's group membership.
pub enum MembershipChange {
    /// The membership now has the requested state.
    Changed,
    /// The user does not exist.
    UserNotFound,
    /// The group does not exist.
    GroupNotFound,
}

const GROUP_COLUMNS: &str = "g.id, g.name, g.parent_id, rs_group_path(g.realm_id, g.id) AS path, (SELECT count(*) FROM groups c WHERE c.realm_id = g.realm_id AND c.parent_id = g.id) AS sub_group_count";

fn group_row(row: &PgRow) -> Result<GroupRecord, StorageError> {
    Ok(GroupRecord {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        parent_id: row.try_get("parent_id")?,
        path: row.try_get("path")?,
        sub_group_count: row.try_get("sub_group_count")?,
    })
}

/// Whether a group other than `id` under `parent_id` (the top level for
/// `None`) has the name.
async fn sibling_named(
    connection: &mut sqlx::PgConnection,
    realm_id: &str,
    parent_id: Option<&str>,
    name: &str,
    id: &str,
) -> Result<bool, StorageError> {
    Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM groups WHERE realm_id = $1 AND parent_id IS NOT DISTINCT FROM $2 AND name = $3 AND id <> $4)")
        .bind(realm_id).bind(parent_id).bind(name).bind(id).fetch_one(connection).await?)
}

impl Storage {
    /// Lists top-level groups, or the direct children of `parent_id`, by name.
    pub async fn groups(
        &self,
        realm_id: &str,
        parent_id: Option<&str>,
    ) -> Result<Vec<GroupRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query(&format!("SELECT {GROUP_COLUMNS} FROM groups g WHERE g.realm_id = $1 AND g.parent_id IS NOT DISTINCT FROM $2 ORDER BY g.name"))
            .bind(realm_id).bind(parent_id).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter().map(group_row).collect()
    }

    /// Reads one group by identifier.
    pub async fn group(
        &self,
        realm_id: &str,
        id: &str,
    ) -> Result<Option<GroupRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let row = sqlx::query(&format!(
            "SELECT {GROUP_COLUMNS} FROM groups g WHERE g.realm_id = $1 AND g.id = $2"
        ))
        .bind(realm_id)
        .bind(id)
        .fetch_optional(tx.connection())
        .await?;
        tx.commit().await?;
        row.as_ref().map(group_row).transpose()
    }

    /// Counts every group in the realm, subgroups included.
    pub async fn count_groups(&self, realm_id: &str) -> Result<i64, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let count = sqlx::query_scalar("SELECT count(*) FROM groups WHERE realm_id = $1")
            .bind(realm_id)
            .fetch_one(tx.connection())
            .await?;
        tx.commit().await?;
        Ok(count)
    }

    /// Renames a group unless a sibling, or another top-level group, has
    /// the name.
    pub async fn rename_group(
        &self,
        realm_id: &str,
        id: &str,
        name: &str,
        actor: &Actor,
    ) -> Result<GroupChange, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let parent: Option<Option<String>> = sqlx::query_scalar(
            "SELECT parent_id FROM groups WHERE realm_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(realm_id)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
        let Some(parent) = parent else {
            tx.commit().await?;
            return Ok(GroupChange::NotFound);
        };
        if sibling_named(conn, realm_id, parent.as_deref(), name, id).await? {
            tx.commit().await?;
            return Ok(GroupChange::Exists);
        }
        sqlx::query("UPDATE groups SET name = $3 WHERE realm_id = $1 AND id = $2")
            .bind(realm_id)
            .bind(id)
            .bind(name)
            .execute(&mut *conn)
            .await?;
        audit(conn, actor, "group_updated").await?;
        tx.commit().await?;
        Ok(GroupChange::Changed)
    }

    /// Moves a group under a new parent, or to the top level for `None`.
    /// Moving a group under itself changes nothing, as in the reference;
    /// moving it under one of its subgroups is refused.
    pub async fn move_group(
        &self,
        realm_id: &str,
        id: &str,
        parent_id: Option<&str>,
        actor: &Actor,
    ) -> Result<GroupChange, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let name: Option<String> = sqlx::query_scalar(
            "SELECT name FROM groups WHERE realm_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(realm_id)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
        let Some(name) = name else {
            tx.commit().await?;
            return Ok(GroupChange::NotFound);
        };
        if parent_id == Some(id) {
            tx.commit().await?;
            return Ok(GroupChange::Changed);
        }
        if let Some(parent_id) = parent_id {
            // The new parent's ancestors, itself included; the group must not be one.
            let ancestors: Vec<String> = sqlx::query_scalar("WITH RECURSIVE up(id, parent_id, depth) AS (SELECT id, parent_id, 0 FROM groups WHERE realm_id = $1 AND id = $2 UNION ALL SELECT g.id, g.parent_id, u.depth + 1 FROM groups g JOIN up u ON g.realm_id = $1 AND g.id = u.parent_id WHERE u.depth < 64) SELECT id FROM up")
                .bind(realm_id).bind(parent_id).fetch_all(&mut *conn).await?;
            if ancestors.is_empty() {
                tx.commit().await?;
                return Ok(GroupChange::ParentNotFound);
            }
            if ancestors.iter().any(|ancestor| ancestor == id) {
                tx.commit().await?;
                return Ok(GroupChange::Cycle);
            }
        }
        if sibling_named(conn, realm_id, parent_id, &name, id).await? {
            tx.commit().await?;
            return Ok(GroupChange::Exists);
        }
        sqlx::query("UPDATE groups SET parent_id = $3 WHERE realm_id = $1 AND id = $2")
            .bind(realm_id)
            .bind(id)
            .bind(parent_id)
            .execute(&mut *conn)
            .await?;
        audit(conn, actor, "group_moved").await?;
        tx.commit().await?;
        Ok(GroupChange::Changed)
    }

    /// Creates a top-level group, or a child of `parent_id`.
    pub async fn create_group(
        &self,
        realm_id: &str,
        id: &str,
        parent_id: Option<&str>,
        name: &str,
        actor: &Actor,
    ) -> Result<GroupCreation, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        if let Some(parent_id) = parent_id {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM groups WHERE realm_id = $1 AND id = $2 FOR KEY SHARE)")
                .bind(realm_id).bind(parent_id).fetch_one(&mut *conn).await?;
            if !exists {
                tx.commit().await?;
                return Ok(GroupCreation::ParentNotFound);
            }
        }
        let created: Option<String> = sqlx::query_scalar("INSERT INTO groups (realm_id, id, parent_id, name) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING RETURNING id")
            .bind(realm_id).bind(id).bind(parent_id).bind(name).fetch_optional(&mut *conn).await?;
        if created.is_none() {
            tx.commit().await?;
            return Ok(GroupCreation::Exists);
        }
        let row = sqlx::query(&format!(
            "SELECT {GROUP_COLUMNS} FROM groups g WHERE g.realm_id = $1 AND g.id = $2"
        ))
        .bind(realm_id)
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;
        audit(conn, actor, "group_created").await?;
        tx.commit().await?;
        Ok(GroupCreation::Created(group_row(&row)?))
    }

    /// Deletes a group with its subgroups and memberships; false if missing.
    pub async fn delete_group(
        &self,
        realm_id: &str,
        id: &str,
        actor: &Actor,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let deleted = sqlx::query("DELETE FROM groups WHERE realm_id = $1 AND id = $2")
            .bind(realm_id)
            .bind(id)
            .execute(&mut *conn)
            .await?
            .rows_affected();
        if deleted == 0 {
            tx.commit().await?;
            return Ok(false);
        }
        audit(conn, actor, "group_deleted").await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Adds a user to a group or removes them; repeating a change is harmless.
    pub async fn change_membership(
        &self,
        realm_id: &str,
        user_id: &str,
        group_id: &str,
        join: bool,
        actor: &Actor,
    ) -> Result<MembershipChange, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let (user, group): (bool, bool) = sqlx::query_as("SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id = $2), EXISTS (SELECT 1 FROM groups WHERE realm_id = $1 AND id = $3)")
            .bind(realm_id).bind(user_id).bind(group_id).fetch_one(&mut *conn).await?;
        let result = if !user {
            MembershipChange::UserNotFound
        } else if !group {
            MembershipChange::GroupNotFound
        } else {
            let statement = if join {
                "INSERT INTO group_members (realm_id, group_id, user_id) VALUES ($1, $3, $2) ON CONFLICT DO NOTHING"
            } else {
                "DELETE FROM group_members WHERE realm_id = $1 AND user_id = $2 AND group_id = $3"
            };
            sqlx::query(statement)
                .bind(realm_id)
                .bind(user_id)
                .bind(group_id)
                .execute(&mut *conn)
                .await?;
            audit(
                conn,
                actor,
                if join {
                    "group_member_added"
                } else {
                    "group_member_removed"
                },
            )
            .await?;
            MembershipChange::Changed
        };
        tx.commit().await?;
        Ok(result)
    }

    /// Lists a user's groups by path, or `None` if the user is missing.
    pub async fn user_groups(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Option<Vec<GroupRecord>>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id = $2)",
        )
        .bind(realm_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;
        let groups = if exists {
            let rows = sqlx::query(&format!("SELECT {GROUP_COLUMNS} FROM groups g JOIN group_members m ON m.realm_id = g.realm_id AND m.group_id = g.id WHERE g.realm_id = $1 AND m.user_id = $2 ORDER BY path"))
                .bind(realm_id).bind(user_id).fetch_all(&mut *conn).await?;
            Some(rows.iter().map(group_row).collect::<Result<_, _>>()?)
        } else {
            None
        };
        tx.commit().await?;
        Ok(groups)
    }

    /// Lists a group's direct members by username.
    pub async fn group_members(
        &self,
        realm_id: &str,
        group_id: &str,
    ) -> Result<Vec<UserRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query(&format!("SELECT {USER_COLUMNS} FROM users WHERE realm_id = $1 AND id IN (SELECT user_id FROM group_members WHERE realm_id = $1 AND group_id = $2) ORDER BY username_normalized"))
            .bind(realm_id).bind(group_id).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter().map(user_row).collect()
    }
}
