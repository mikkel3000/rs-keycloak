//! Admin REST routes for the realm's required actions.
//!
//! Follows `tests/reference/required-action-admin-observations.json`. Only
//! the five actions this server performs are listed; each can be disabled,
//! which stops it at login while users keep it assigned, or made a default
//! for new users. Priorities are fixed.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::get;
use rs_keycloak_storage_postgres::RequiredActionSetting;
use serde_json::{Value, json};

use super::users::{json_response, realm_id};
use super::{Access, AdminError, authorize};
use crate::oidc::OidcState;

/// The modelled actions in the reference's priority order, with their names
/// and priorities.
const ACTIONS: [(&str, &str, i64); 5] = [
    ("UPDATE_PROFILE", "Update Profile", 40),
    ("VERIFY_EMAIL", "Verify Email", 50),
    ("CONFIGURE_TOTP", "Configure OTP", 54),
    ("UPDATE_PASSWORD", "Update Password", 57),
    ("VERIFY_PROFILE", "Verify Profile", 100),
];

pub(super) fn routes() -> Router<OidcState> {
    Router::new()
        .route(
            "/admin/realms/{realm}/authentication/required-actions",
            get(list_actions),
        )
        .route(
            "/admin/realms/{realm}/authentication/required-actions/{alias}",
            get(read_action).put(update_action),
        )
}

fn action_not_found() -> AdminError {
    AdminError::Error(
        StatusCode::NOT_FOUND,
        "Failed to find required action".into(),
    )
}

fn unparsable() -> AdminError {
    AdminError::OAuth(
        StatusCode::BAD_REQUEST,
        "unknown_error",
        "Cannot parse the JSON",
    )
}

/// The action's representation, with the realm's stored setting or the
/// defaults: enabled and not default.
fn representation(
    (alias, name, priority): (&str, &str, i64),
    settings: &[RequiredActionSetting],
) -> Value {
    let setting = settings.iter().find(|setting| setting.alias == alias);
    json!({
        "alias": alias,
        "name": name,
        "providerId": alias,
        "enabled": setting.is_none_or(|setting| setting.enabled),
        "defaultAction": setting.is_some_and(|setting| setting.default_action),
        "priority": priority,
        "config": {},
    })
}

/// Every action's representation for a realm's settings.
pub(super) fn all_actions(settings: &[RequiredActionSetting]) -> Vec<Value> {
    ACTIONS
        .into_iter()
        .map(|action| representation(action, settings))
        .collect()
}

fn action(alias: &str) -> Result<(&'static str, &'static str, i64), AdminError> {
    ACTIONS
        .into_iter()
        .find(|(known, _, _)| *known == alias)
        .ok_or_else(action_not_found)
}

async fn list_actions(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewRealm).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let settings = state.storage.required_action_settings(&realm_id).await?;
    Ok(json_response(Value::Array(all_actions(&settings))))
}

async fn read_action(
    State(state): State<OidcState>,
    Path((realm, alias)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewRealm).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let action = action(&alias)?;
    let settings = state.storage.required_action_settings(&realm_id).await?;
    Ok(json_response(representation(action, &settings)))
}

/// Replaces an action's flags; the read-only fields may be sent back as
/// read, and other values are refused rather than ignored.
async fn update_action(
    State(state): State<OidcState>,
    Path((realm, alias)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageRealm).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let (alias, name, priority) = action(&alias)?;
    let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(&body) else {
        return Err(unparsable());
    };
    let flag = |name: &str| match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(unparsable()),
    };
    let fixed = [
        ("alias", json!(alias)),
        ("providerId", json!(alias)),
        ("name", json!(name)),
        ("priority", json!(priority)),
        ("config", json!({})),
    ];
    if let Some(field) = fields.keys().find(|key| {
        !matches!(key.as_str(), "enabled" | "defaultAction")
            && !fixed.iter().any(|(fixed, _)| fixed == key)
    }) {
        return Err(AdminError::bad_request(format!(
            "Unsupported required action field: {field}"
        )));
    }
    if let Some((field, _)) = fixed.iter().find(|(field, value)| {
        fields
            .get(*field)
            .is_some_and(|given| !given.is_null() && given != value)
    }) {
        return Err(AdminError::bad_request(format!(
            "Unsupported required action setting: {field}"
        )));
    }
    let settings = state.storage.required_action_settings(&realm_id).await?;
    let current = representation((alias, name, priority), &settings);
    let stored = |name: &str| {
        current
            .get(name)
            .and_then(Value::as_bool)
            .unwrap_or_default()
    };
    let setting = RequiredActionSetting {
        alias: alias.to_owned(),
        enabled: flag("enabled")?.unwrap_or(stored("enabled")),
        default_action: flag("defaultAction")?.unwrap_or(stored("defaultAction")),
    };
    // VERIFY_PROFILE runs from the profile's state and is never assigned,
    // so it cannot be given to new users.
    if alias == "VERIFY_PROFILE" && setting.default_action {
        return Err(AdminError::bad_request(
            "Unsupported required action setting: defaultAction",
        ));
    }
    state
        .storage
        .save_required_action(&realm_id, &setting, &actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
