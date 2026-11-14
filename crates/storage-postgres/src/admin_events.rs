//! Stored admin events: written after an admin API change in a realm with
//! admin events on, listed with the admin API's filters and cleared by the
//! admin API.

use sqlx::Row;

use crate::event_settings::{EVENT_SETTING_COLUMNS, EventSettings, event_settings_row};
use crate::{Storage, StorageError};

/// An admin event to store.
pub struct NewAdminEvent<'a> {
    /// Event id.
    pub id: &'a str,
    /// The realm the change was made in.
    pub realm_id: &'a str,
    /// `CREATE`, `UPDATE`, `DELETE` or `ACTION`.
    pub operation_type: &'a str,
    /// The reference's resource type, such as `USER`.
    pub resource_type: &'a str,
    /// The changed resource below the realm, if any.
    pub resource_path: Option<&'a str>,
    /// The request representation, when the realm keeps it.
    pub representation: Option<&'a str>,
    /// The realm of the acting token.
    pub auth_realm_id: &'a str,
    /// The `clientId` of the acting token, resolved to the client's id.
    pub auth_client: &'a str,
    /// The acting user.
    pub auth_user_id: &'a str,
    /// The caller's address.
    pub ip_address: Option<&'a str>,
}

/// A stored admin event.
pub struct AdminEventRecord {
    /// Event id.
    pub id: String,
    /// Epoch milliseconds.
    pub time: i64,
    /// Realm id.
    pub realm_id: String,
    /// Operation type.
    pub operation_type: String,
    /// Resource type.
    pub resource_type: String,
    /// Resource path, if any.
    pub resource_path: Option<String>,
    /// Representation, if kept.
    pub representation: Option<String>,
    /// The realm of the acting token.
    pub auth_realm_id: String,
    /// The acting client's id, if it still exists when the event is written.
    pub auth_client_id: Option<String>,
    /// The acting user.
    pub auth_user_id: String,
    /// The caller's address.
    pub ip_address: Option<String>,
}

/// Filters of an admin event listing; times are inclusive epoch
/// milliseconds.
#[derive(Default)]
pub struct AdminEventQuery {
    /// Operation types; empty takes every type.
    pub operation_types: Vec<String>,
    /// Resource types; empty takes every type.
    pub resource_types: Vec<String>,
    /// A resource path where `*` matches any text.
    pub resource_path: Option<String>,
    /// The acting token's realm id.
    pub auth_realm: Option<String>,
    /// The acting client's id.
    pub auth_client: Option<String>,
    /// The acting user's id.
    pub auth_user: Option<String>,
    /// The caller's address.
    pub auth_ip_address: Option<String>,
    /// Earliest time.
    pub from: Option<i64>,
    /// Latest time.
    pub to: Option<i64>,
    /// Events skipped.
    pub first: i64,
    /// Events returned at most.
    pub max: i64,
    /// Oldest first instead of newest first.
    pub ascending: bool,
}

const ADMIN_EVENT_COLUMNS: &str = "id, event_time, realm_id, operation_type, resource_type, resource_path, representation, auth_realm_id, auth_client_id, auth_user_id, ip_address";

/// Turns a resource path filter into a `LIKE` pattern: `*` matches any
/// text and the pattern characters of the path match themselves.
fn like_pattern(path: &str) -> String {
    let mut pattern = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            '*' => pattern.push('%'),
            '%' | '_' | '\\' => {
                pattern.push('\\');
                pattern.push(c);
            }
            c => pattern.push(c),
        }
    }
    pattern
}

impl Storage {
    /// Reads a realm's id and event settings by name.
    pub async fn realm_event_settings(
        &self,
        name: &str,
    ) -> Result<Option<(String, EventSettings)>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query(&format!(
            "SELECT id, {EVENT_SETTING_COLUMNS} FROM realms WHERE name = $1"
        ))
        .bind(name)
        .fetch_optional(tx.connection())
        .await?;
        tx.commit().await?;
        row.map(|row| Ok((row.try_get("id")?, event_settings_row(&row)?)))
            .transpose()
    }

    /// Stores an admin event.
    pub async fn record_admin_event(&self, event: &NewAdminEvent<'_>) -> Result<(), StorageError> {
        let mut tx = self.begin_request(true).await?;
        sqlx::query("INSERT INTO admin_events (id, realm_id, event_time, operation_type, resource_type, resource_path, representation, auth_realm_id, auth_client_id, auth_user_id, ip_address) VALUES ($1, $2, (extract(epoch FROM clock_timestamp()) * 1000)::bigint, $3, $4, $5, $6, $7, (SELECT id FROM clients WHERE realm_id = $7 AND client_id = $8), $9, $10)")
            .bind(event.id).bind(event.realm_id).bind(event.operation_type).bind(event.resource_type)
            .bind(event.resource_path).bind(event.representation).bind(event.auth_realm_id)
            .bind(event.auth_client).bind(event.auth_user_id).bind(event.ip_address)
            .execute(tx.connection()).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Lists a realm's admin events.
    pub async fn admin_events(
        &self,
        realm_id: &str,
        query: &AdminEventQuery,
    ) -> Result<Vec<AdminEventRecord>, StorageError> {
        let order = if query.ascending { "ASC" } else { "DESC" };
        let path = query.resource_path.as_deref().map(like_pattern);
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query(&format!("SELECT {ADMIN_EVENT_COLUMNS} FROM admin_events WHERE realm_id = $1 AND (cardinality($2::text[]) = 0 OR operation_type = ANY($2)) AND (cardinality($3::text[]) = 0 OR resource_type = ANY($3)) AND ($4::text IS NULL OR resource_path LIKE $4) AND ($5::text IS NULL OR auth_realm_id = $5) AND ($6::text IS NULL OR auth_client_id = $6) AND ($7::text IS NULL OR auth_user_id = $7) AND ($8::text IS NULL OR ip_address = $8) AND ($9::bigint IS NULL OR event_time >= $9) AND ($10::bigint IS NULL OR event_time <= $10) ORDER BY event_time {order}, id {order} OFFSET $11 LIMIT $12"))
            .bind(realm_id).bind(&query.operation_types).bind(&query.resource_types).bind(path)
            .bind(query.auth_realm.as_deref()).bind(query.auth_client.as_deref())
            .bind(query.auth_user.as_deref()).bind(query.auth_ip_address.as_deref())
            .bind(query.from).bind(query.to).bind(query.first).bind(query.max)
            .fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| {
                Ok(AdminEventRecord {
                    id: row.try_get("id")?,
                    time: row.try_get("event_time")?,
                    realm_id: row.try_get("realm_id")?,
                    operation_type: row.try_get("operation_type")?,
                    resource_type: row.try_get("resource_type")?,
                    resource_path: row.try_get("resource_path")?,
                    representation: row.try_get("representation")?,
                    auth_realm_id: row.try_get("auth_realm_id")?,
                    auth_client_id: row.try_get("auth_client_id")?,
                    auth_user_id: row.try_get("auth_user_id")?,
                    ip_address: row.try_get("ip_address")?,
                })
            })
            .collect()
    }

    /// Removes every admin event of a realm.
    pub async fn clear_admin_events(&self, realm_id: &str) -> Result<(), StorageError> {
        let mut tx = self.begin_request(false).await?;
        sqlx::query("DELETE FROM admin_events WHERE realm_id = $1")
            .bind(realm_id)
            .execute(tx.connection())
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::like_pattern;

    #[test]
    fn stars_match_any_text_and_pattern_characters_match_themselves() {
        assert_eq!(like_pattern("users/*"), "users/%");
        assert_eq!(like_pattern("roles/a_b%"), "roles/a\\_b\\%");
    }
}
