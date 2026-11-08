//! The realm representation's login-flow settings: rememberMe and its
//! session lifetimes, registrationAllowed and the OTP policy, read on
//! realm creation and update and shown in the representation.

use axum::http::StatusCode;
use rs_keycloak_storage_postgres::{LoginSettingChanges, LoginSettings, OtpPolicy};
use serde_json::{Map, Value, json};

use super::AdminError;
use crate::oidc::{SSO_SESSION_IDLE_TIMEOUT, SSO_SESSION_MAX_LIFESPAN};

/// The realm fields this module reads.
pub(super) const FIELDS: [&str; 12] = [
    "rememberMe",
    "ssoSessionIdleTimeoutRememberMe",
    "ssoSessionMaxLifespanRememberMe",
    "registrationAllowed",
    "otpPolicyType",
    "otpPolicyAlgorithm",
    "otpPolicyInitialCounter",
    "otpPolicyDigits",
    "otpPolicyLookAheadWindow",
    "otpPolicyPeriod",
    "otpPolicyCodeReusable",
    "otpSupportedApplications",
];

/// The realm fields [`represent`] adds, which partial import leaves alone.
pub(super) const REPRESENTED: [&str; 14] = [
    "otpPolicyType",
    "otpPolicyAlgorithm",
    "otpPolicyInitialCounter",
    "otpPolicyDigits",
    "otpPolicyLookAheadWindow",
    "otpPolicyPeriod",
    "otpPolicyCodeReusable",
    "otpSupportedApplications",
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

fn text(fields: &Map<String, Value>, name: &str) -> Result<Option<String>, AdminError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.len() <= 255 => Ok(Some(value.clone())),
        Some(Value::String(_)) => Err(AdminError::bad_request(format!("Invalid {name}"))),
        Some(_) => Err(unparsable()),
    }
}

/// The OTP policy a representation gives. As
/// `DefaultExportImportManager.toPolicy`, a policy is read only with its
/// type, and then replaces the whole policy, with 0, null or false for
/// fields it leaves out; `otpSupportedApplications` is read-only.
fn otp_policy(fields: &Map<String, Value>) -> Result<Option<OtpPolicy>, AdminError> {
    let algorithm = text(fields, "otpPolicyAlgorithm")?;
    let digits = number(fields, "otpPolicyDigits")?;
    let period = number(fields, "otpPolicyPeriod")?;
    let look_ahead = number(fields, "otpPolicyLookAheadWindow")?;
    let initial_counter = number(fields, "otpPolicyInitialCounter")?;
    let code_reusable = flag(fields, "otpPolicyCodeReusable")?;
    let Some(kind) = text(fields, "otpPolicyType")? else {
        return Ok(None);
    };
    Ok(Some(OtpPolicy {
        kind,
        algorithm,
        digits: digits.unwrap_or(0),
        period: period.unwrap_or(0),
        look_ahead: look_ahead.unwrap_or(0),
        initial_counter: initial_counter.unwrap_or(0),
        code_reusable: code_reusable.unwrap_or(false),
    }))
}

/// Reads the settings a representation gives.
pub(super) fn parse(fields: &Map<String, Value>) -> Result<LoginSettingChanges, AdminError> {
    Ok(LoginSettingChanges {
        remember_me: flag(fields, "rememberMe")?,
        sso_session_idle_timeout_remember_me: number(fields, "ssoSessionIdleTimeoutRememberMe")?,
        sso_session_max_lifespan_remember_me: number(fields, "ssoSessionMaxLifespanRememberMe")?,
        registration_allowed: flag(fields, "registrationAllowed")?,
        otp_policy: otp_policy(fields)?,
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
    let otp = &settings.otp_policy;
    representation["otpPolicyType"] = json!(otp.kind);
    representation["otpPolicyAlgorithm"] = json!(otp.algorithm);
    representation["otpPolicyInitialCounter"] = json!(otp.initial_counter);
    representation["otpPolicyDigits"] = json!(otp.digits);
    representation["otpPolicyLookAheadWindow"] = json!(otp.look_ahead);
    representation["otpPolicyPeriod"] = json!(otp.period);
    representation["otpPolicyCodeReusable"] = json!(otp.code_reusable);
    representation["otpSupportedApplications"] =
        json!(crate::otp_policy::supported_applications(otp));
}
