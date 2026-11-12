//! Realm event settings: eventsEnabled, eventsExpiration, eventsListeners,
//! enabledEventTypes, adminEventsEnabled and adminEventsDetailsEnabled, in
//! realm representations and through GET and PUT
//! `/admin/realms/{realm}/events/config`, following
//! `tests/reference/event-config-observations.json`.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::get;
use rs_keycloak_storage_postgres::{EventSettingChanges, EventSettings};
use serde_json::{Map, Value, json};

use super::{Access, AdminError, authorize, json_text};
use crate::events::DEFAULT_EVENT_TYPES;
use crate::oidc::OidcState;

pub(super) fn routes() -> Router<OidcState> {
    Router::new().route(
        "/admin/realms/{realm}/events/config",
        get(read_config).put(update_config),
    )
}

/// The realm representation fields this module reads.
const FIELDS: [&str; 6] = [
    "eventsEnabled",
    "eventsExpiration",
    "eventsListeners",
    "enabledEventTypes",
    "adminEventsEnabled",
    "adminEventsDetailsEnabled",
];

/// The event listeners a realm can name. `jboss-logging` is the
/// reference's default; this server writes no event log lines for it.
const LISTENERS: [&str; 1] = ["jboss-logging"];

/// Whether this module reads a realm field.
pub(super) fn reads(field: &str) -> bool {
    FIELDS.contains(&field)
}

fn unparsable() -> AdminError {
    AdminError::OAuth(
        StatusCode::BAD_REQUEST,
        "unknown_error",
        "Cannot parse the JSON",
    )
}

fn flag(fields: &Map<String, Value>, name: &str) -> Result<Option<bool>, AdminError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(unparsable()),
    }
}

/// A list of strings, sorted without repeats, as the reference keeps it in
/// a set.
fn names(fields: &Map<String, Value>, name: &str) -> Result<Option<Vec<String>>, AdminError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => {
            let mut names = items
                .iter()
                .map(|item| match item {
                    Value::String(name) if name.len() <= 255 => Ok(name.clone()),
                    _ => Err(unparsable()),
                })
                .collect::<Result<Vec<_>, _>>()?;
            names.sort();
            names.dedup();
            Ok(Some(names))
        }
        Some(_) => Err(unparsable()),
    }
}

/// Reads the event fields of a realm representation; absent fields keep
/// their value. Unknown listeners are refused, as the events config
/// resource refuses them.
pub(super) fn parse(fields: &Map<String, Value>) -> Result<EventSettingChanges, AdminError> {
    let events_expiration = match fields.get("eventsExpiration") {
        None | Some(Value::Null) => None,
        Some(value) => Some(expiration(value)?),
    };
    let events_listeners = names(fields, "eventsListeners")?;
    if events_listeners
        .iter()
        .flatten()
        .any(|listener| !LISTENERS.contains(&listener.as_str()))
    {
        return Err(AdminError::Error(
            StatusCode::BAD_REQUEST,
            "Unknown event listener".to_owned(),
        ));
    }
    Ok(EventSettingChanges {
        events_enabled: flag(fields, "eventsEnabled")?,
        events_expiration,
        events_listeners,
        enabled_event_types: names(fields, "enabledEventTypes")?,
        admin_events_enabled: flag(fields, "adminEventsEnabled")?,
        admin_events_details_enabled: flag(fields, "adminEventsDetailsEnabled")?,
    })
}

/// An expiration in seconds; 0 or less removes it, as the reference shows
/// no expiration for 0.
fn expiration(value: &Value) -> Result<Option<i64>, AdminError> {
    let seconds = value.as_i64().ok_or_else(unparsable)?;
    Ok((seconds > 0).then_some(seconds))
}

/// Adds the event settings to a realm representation.
pub(super) fn represent(settings: &EventSettings, representation: &mut Value) {
    representation["eventsEnabled"] = json!(settings.events_enabled);
    if let Some(expiration) = settings.events_expiration {
        representation["eventsExpiration"] = json!(expiration);
    }
    representation["eventsListeners"] = json!(settings.events_listeners);
    representation["enabledEventTypes"] = json!(settings.enabled_event_types);
    representation["adminEventsEnabled"] = json!(settings.admin_events_enabled);
    representation["adminEventsDetailsEnabled"] = json!(settings.admin_events_details_enabled);
}

/// The events config representation: the realm's settings, with the
/// default event types when the realm names none.
fn config_representation(settings: &EventSettings) -> Value {
    let mut config = json!({});
    represent(settings, &mut config);
    if settings.enabled_event_types.is_empty() {
        config["enabledEventTypes"] = json!(DEFAULT_EVENT_TYPES.as_slice());
    }
    config
}

async fn read_config(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewEvents).await?;
    let realm = state
        .storage
        .realm_by_name(&realm)
        .await?
        .ok_or(AdminError::RealmNotFound)?;
    Ok(json_text(&config_representation(&realm.events)))
}

/// Replaces the events config as `RealmManager.updateRealmEventsConfig`
/// does: eventsEnabled and eventsExpiration take their absent values,
/// the other fields keep theirs when absent.
async fn update_config(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    authorize(&state, &headers, &realm, Access::ManageEvents).await?;
    let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(&body) else {
        return Err(unparsable());
    };
    let mut changes = parse(&fields)?;
    changes.events_enabled = Some(changes.events_enabled.unwrap_or(false));
    changes.events_expiration = Some(changes.events_expiration.flatten());
    match state
        .storage
        .update_event_settings(&realm, &changes)
        .await?
    {
        Some(_) => Ok(StatusCode::NO_CONTENT),
        None => Err(AdminError::RealmNotFound),
    }
}
