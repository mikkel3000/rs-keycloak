//! Stored login events: written when a realm's settings store their type,
//! listed with the admin API's filters and cleared by the admin API.

use sqlx::Row;

use crate::brute_force;
use crate::event_settings::{EVENT_SETTING_COLUMNS, EventSettings, event_settings_row};
use crate::{Storage, StorageError};

/// A login event to store.
pub struct NewLoginEvent<'a> {
    /// Event id.
    pub id: &'a str,
    /// Realm id.
    pub realm_id: &'a str,
    /// Event type, such as `LOGIN`.
    pub event_type: &'a str,
    /// The client's `clientId`, if known.
    pub client_id: Option<&'a str>,
    /// The user, if known.
    pub user_id: Option<&'a str>,
    /// The user session, if one exists.
    pub session_id: Option<&'a str>,
    /// The browser's address.
    pub ip_address: Option<&'a str>,
    /// The error of an `_ERROR` event.
    pub error: Option<&'a str>,
    /// Details as a JSON object text.
    pub details: &'a str,
}

/// A stored login event.
pub struct LoginEventRecord {
    /// Event id.
    pub id: String,
    /// Epoch milliseconds.
    pub time: i64,
    /// Event type.
    pub event_type: String,
    /// Realm id.
    pub realm_id: String,
    /// The client's `clientId`, if known.
    pub client_id: Option<String>,
    /// The user, if known.
    pub user_id: Option<String>,
    /// The user session, if any.
    pub session_id: Option<String>,
    /// The browser's address.
    pub ip_address: Option<String>,
    /// The error, if any.
    pub error: Option<String>,
    /// Details as a JSON object text.
    pub details: String,
}

/// Filters of a login event listing; times are inclusive epoch
/// milliseconds.
#[derive(Default)]
pub struct LoginEventQuery {
    /// Event types; empty takes every type.
    pub types: Vec<String>,
    /// The client's `clientId`.
    pub client: Option<String>,
    /// The user id.
    pub user: Option<String>,
    /// The browser's address.
    pub ip_address: Option<String>,
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

/// Who a refused login named.
pub enum LoginSubject {
    /// No user has the username or email.
    Unknown,
    /// The named user.
    User {
        /// User id.
        id: String,
        /// Whether the user is enabled.
        enabled: bool,
        /// Whether brute-force detection holds the user.
        locked: bool,
    },
}

const EVENT_COLUMNS: &str = "id, event_time, event_type, realm_id, client_id, user_id, session_id, ip_address, error, details::text AS details";

impl Storage {
    /// Reads a realm's event settings by realm id.
    pub async fn event_settings(
        &self,
        realm_id: &str,
    ) -> Result<Option<EventSettings>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query(&format!(
            "SELECT {EVENT_SETTING_COLUMNS} FROM realms WHERE id = $1"
        ))
        .bind(realm_id)
        .fetch_optional(tx.connection())
        .await?;
        tx.commit().await?;
        row.as_ref().map(event_settings_row).transpose()
    }

    /// Stores a login event, and removes up to 64 of the realm's events
    /// older than its expiration.
    pub async fn record_login_event(
        &self,
        event: &NewLoginEvent<'_>,
        expiration: Option<i64>,
    ) -> Result<(), StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        sqlx::query("INSERT INTO login_events (id, realm_id, event_time, event_type, client_id, user_id, session_id, ip_address, error, details) VALUES ($1, $2, (extract(epoch FROM clock_timestamp()) * 1000)::bigint, $3, $4, $5, $6, $7, $8, $9::jsonb)")
            .bind(event.id).bind(event.realm_id).bind(event.event_type).bind(event.client_id)
            .bind(event.user_id).bind(event.session_id).bind(event.ip_address).bind(event.error)
            .bind(event.details)
            .execute(&mut *conn).await?;
        if let Some(seconds) = expiration {
            sqlx::query("DELETE FROM login_events WHERE id IN (SELECT id FROM login_events WHERE realm_id = $1 AND event_time < (extract(epoch FROM clock_timestamp()) * 1000)::bigint - $2 * 1000 LIMIT 64)")
                .bind(event.realm_id).bind(seconds)
                .execute(&mut *conn).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Lists a realm's login events.
    pub async fn login_events(
        &self,
        realm_id: &str,
        query: &LoginEventQuery,
    ) -> Result<Vec<LoginEventRecord>, StorageError> {
        let order = if query.ascending { "ASC" } else { "DESC" };
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query(&format!("SELECT {EVENT_COLUMNS} FROM login_events WHERE realm_id = $1 AND (cardinality($2::text[]) = 0 OR event_type = ANY($2)) AND ($3::text IS NULL OR client_id = $3) AND ($4::text IS NULL OR user_id = $4) AND ($5::text IS NULL OR ip_address = $5) AND ($6::bigint IS NULL OR event_time >= $6) AND ($7::bigint IS NULL OR event_time <= $7) ORDER BY event_time {order}, id {order} OFFSET $8 LIMIT $9"))
            .bind(realm_id).bind(&query.types).bind(query.client.as_deref())
            .bind(query.user.as_deref()).bind(query.ip_address.as_deref())
            .bind(query.from).bind(query.to).bind(query.first).bind(query.max)
            .fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| {
                Ok(LoginEventRecord {
                    id: row.try_get("id")?,
                    time: row.try_get("event_time")?,
                    event_type: row.try_get("event_type")?,
                    realm_id: row.try_get("realm_id")?,
                    client_id: row.try_get("client_id")?,
                    user_id: row.try_get("user_id")?,
                    session_id: row.try_get("session_id")?,
                    ip_address: row.try_get("ip_address")?,
                    error: row.try_get("error")?,
                    details: row.try_get("details")?,
                })
            })
            .collect()
    }

    /// Removes every login event of a realm.
    pub async fn clear_login_events(&self, realm_id: &str) -> Result<(), StorageError> {
        let mut tx = self.begin_request(false).await?;
        sqlx::query("DELETE FROM login_events WHERE realm_id = $1")
            .bind(realm_id)
            .execute(tx.connection())
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Finds the user a refused login named, by username or, when the realm
    /// allows it, by an email one user has.
    pub async fn login_subject(
        &self,
        realm_id: &str,
        username_normalized: &str,
    ) -> Result<LoginSubject, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let row = sqlx::query("SELECT u.id, u.enabled FROM users u JOIN realms r ON r.id = u.realm_id WHERE u.realm_id = $1 AND u.id = COALESCE((SELECT min(e.id) FROM users e WHERE e.realm_id = $1 AND r.login_with_email_allowed AND strpos($2, '@') > 0 AND e.email_normalized = $2 HAVING count(*) = 1), (SELECT n.id FROM users n WHERE n.realm_id = $1 AND n.username_normalized = $2))")
            .bind(realm_id).bind(username_normalized)
            .fetch_optional(&mut *conn).await?;
        let subject = match row {
            None => LoginSubject::Unknown,
            Some(row) => {
                let id: String = row.try_get("id")?;
                let locked = brute_force::locked(&mut *conn, realm_id, &id).await?;
                LoginSubject::User {
                    id,
                    enabled: row.try_get("enabled")?,
                    locked,
                }
            }
        };
        tx.commit().await?;
        Ok(subject)
    }

    /// What a login event says about an authorization request.
    pub async fn authorization_request_summary(
        &self,
        request_id: &str,
    ) -> Result<Option<RequestSummary>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query("SELECT c.client_id, a.redirect_uri, a.response_mode, c.consent_required FROM authorization_requests a JOIN clients c ON c.realm_id = a.realm_id AND c.id = a.client_id WHERE a.id = $1")
            .bind(request_id)
            .fetch_optional(tx.connection())
            .await?;
        tx.commit().await?;
        row.map(|row| {
            Ok(RequestSummary {
                client_identifier: row.try_get("client_id")?,
                redirect_uri: row.try_get("redirect_uri")?,
                response_mode: row.try_get("response_mode")?,
                consent_required: row.try_get("consent_required")?,
            })
        })
        .transpose()
    }

    /// The user id and username of a user session.
    pub async fn session_user(
        &self,
        realm_id: &str,
        session_id: &str,
    ) -> Result<Option<(String, String)>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query_as("SELECT u.id, u.username FROM user_sessions s JOIN users u ON u.realm_id = s.realm_id AND u.id = s.user_id WHERE s.realm_id = $1 AND s.id = $2")
            .bind(realm_id)
            .bind(session_id)
            .fetch_optional(tx.connection())
            .await?;
        tx.commit().await?;
        Ok(row)
    }
}

/// What a login event says about an authorization request.
pub struct RequestSummary {
    /// The client's `clientId`.
    pub client_identifier: String,
    /// The requested redirect URI.
    pub redirect_uri: String,
    /// `query`, `fragment` or `form_post`.
    pub response_mode: String,
    /// Whether the client asks for consent.
    pub consent_required: bool,
}
