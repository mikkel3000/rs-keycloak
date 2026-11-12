//! Realm event settings: whether login and admin events are stored, which
//! login event types, for how long, and the event listeners. Each is read
//! with the realm and changed by one statement in the realm's create or
//! update transaction, or alone by the events config resource.

use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row};

use crate::{Storage, StorageError};

/// The event settings of a realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventSettings {
    /// Whether login events are stored.
    pub events_enabled: bool,
    /// Seconds a stored login event is kept, if limited.
    pub events_expiration: Option<i64>,
    /// Event listener ids.
    pub events_listeners: Vec<String>,
    /// Login event types stored; empty stands for the types stored by
    /// default.
    pub enabled_event_types: Vec<String>,
    /// Whether admin events are stored.
    pub admin_events_enabled: bool,
    /// Whether admin events keep the request representation.
    pub admin_events_details_enabled: bool,
}

/// Changes to a realm's event settings; `None` keeps one, or for a new
/// realm its default.
#[derive(Clone, Debug, Default)]
pub struct EventSettingChanges {
    /// See [`EventSettings::events_enabled`].
    pub events_enabled: Option<bool>,
    /// See [`EventSettings::events_expiration`]; `Some(None)` removes it.
    pub events_expiration: Option<Option<i64>>,
    /// See [`EventSettings::events_listeners`].
    pub events_listeners: Option<Vec<String>>,
    /// See [`EventSettings::enabled_event_types`].
    pub enabled_event_types: Option<Vec<String>>,
    /// See [`EventSettings::admin_events_enabled`].
    pub admin_events_enabled: Option<bool>,
    /// See [`EventSettings::admin_events_details_enabled`].
    pub admin_events_details_enabled: Option<bool>,
}

/// The realm columns [`event_settings_row`] reads.
pub(crate) const EVENT_SETTING_COLUMNS: &str = "events_enabled, events_expiration, events_listeners, enabled_event_types, admin_events_enabled, admin_events_details_enabled";

pub(crate) fn event_settings_row(row: &PgRow) -> Result<EventSettings, StorageError> {
    Ok(EventSettings {
        events_enabled: row.try_get("events_enabled")?,
        events_expiration: row.try_get("events_expiration")?,
        events_listeners: row.try_get("events_listeners")?,
        enabled_event_types: row.try_get("enabled_event_types")?,
        admin_events_enabled: row.try_get("admin_events_enabled")?,
        admin_events_details_enabled: row.try_get("admin_events_details_enabled")?,
    })
}

/// Applies changes to the realm with this name; returns whether it exists.
pub(crate) async fn change_event_settings(
    connection: &mut PgConnection,
    realm: &str,
    changes: &EventSettingChanges,
) -> Result<bool, StorageError> {
    let changed = sqlx::query("UPDATE realms SET events_enabled = COALESCE($2, events_enabled), events_expiration = CASE WHEN $3 THEN $4 ELSE events_expiration END, events_listeners = COALESCE($5, events_listeners), enabled_event_types = COALESCE($6, enabled_event_types), admin_events_enabled = COALESCE($7, admin_events_enabled), admin_events_details_enabled = COALESCE($8, admin_events_details_enabled) WHERE name = $1")
        .bind(realm)
        .bind(changes.events_enabled)
        .bind(changes.events_expiration.is_some())
        .bind(changes.events_expiration.flatten())
        .bind(changes.events_listeners.as_deref())
        .bind(changes.enabled_event_types.as_deref())
        .bind(changes.admin_events_enabled)
        .bind(changes.admin_events_details_enabled)
        .execute(connection)
        .await?
        .rows_affected();
    Ok(changed > 0)
}

impl Storage {
    /// Applies changes to a realm's event settings; returns the settings
    /// before and after, or `None` if the realm is missing.
    pub async fn update_event_settings(
        &self,
        realm: &str,
        changes: &EventSettingChanges,
    ) -> Result<Option<(EventSettings, EventSettings)>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let read = format!("SELECT {EVENT_SETTING_COLUMNS} FROM realms WHERE name = $1");
        let Some(before) = sqlx::query(&read)
            .bind(realm)
            .fetch_optional(tx.connection())
            .await?
        else {
            tx.commit().await?;
            return Ok(None);
        };
        let before = event_settings_row(&before)?;
        change_event_settings(tx.connection(), realm, changes).await?;
        let after = event_settings_row(
            &sqlx::query(&read)
                .bind(realm)
                .fetch_one(tx.connection())
                .await?,
        )?;
        tx.commit().await?;
        Ok(Some((before, after)))
    }
}
