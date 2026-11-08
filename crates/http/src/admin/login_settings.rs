//! The realm representation's login-flow settings: rememberMe and its
//! session lifetimes and registrationAllowed, read on realm creation and
//! update and shown in the representation.

use axum::http::StatusCode;
use rs_keycloak_storage_postgres::{LoginSettingChanges, LoginSettings};
use serde_json::{Map, Value, json};

use super::AdminError;
use crate::oidc::{SSO_SESSION_IDLE_TIMEOUT, SSO_SESSION_MAX_LIFESPAN};

/// The realm fields this module reads.
pub(super) const FIELDS: [&str; 4] = [
    "rememberMe",
    "ssoSessionIdleTimeoutRememberMe",
    "ssoSessionMaxLifespanRememberMe",
    "registrationAllowed",
];

/// The realm fields [`represent`] adds, which partial import leaves alone.
pub(super) const REPRESENTED: [&str; 6] = [
    "rememberMe",
    "registrationAllowed",
    "ssoSessionIdleTimeout",
    "ssoSessionMaxLifespan",
    "ssoSessionIdleTimeoutRememberMe",
    "ssoSessionMaxLifespanRememberMe",
];

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

/// An integer field; the reference stores any int, so only the JSON type
/// and range are checked.
fn number(fields: &Map<String, Value>, name: &str) -> Result<Option<i32>, AdminError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_i64()
            .and_then(|value| i32::try_from(value).ok())
            .map(Some)
            .ok_or_else(unparsable),
        Some(_) => Err(unparsable()),
    }
}

/// Reads the settings a representation gives.
pub(super) fn parse(fields: &Map<String, Value>) -> Result<LoginSettingChanges, AdminError> {
    Ok(LoginSettingChanges {
        remember_me: flag(fields, "rememberMe")?,
        sso_session_idle_timeout_remember_me: number(fields, "ssoSessionIdleTimeoutRememberMe")?,
        sso_session_max_lifespan_remember_me: number(fields, "ssoSessionMaxLifespanRememberMe")?,
        registration_allowed: flag(fields, "registrationAllowed")?,
    })
}

/// Adds the settings to a realm representation, with the session lifetimes
/// this server keeps.
pub(super) fn represent(settings: &LoginSettings, representation: &mut Value) {
    representation["rememberMe"] = json!(settings.remember_me);
    representation["registrationAllowed"] = json!(settings.registration_allowed);
    representation["ssoSessionIdleTimeout"] = json!(SSO_SESSION_IDLE_TIMEOUT);
    representation["ssoSessionMaxLifespan"] = json!(SSO_SESSION_MAX_LIFESPAN);
    representation["ssoSessionIdleTimeoutRememberMe"] =
        json!(settings.sso_session_idle_timeout_remember_me);
    representation["ssoSessionMaxLifespanRememberMe"] =
        json!(settings.sso_session_max_lifespan_remember_me);
}
