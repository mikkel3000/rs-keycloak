//! Login events written by the login flow, as the reference's
//! `EventBuilder` writes them, and the request-scoped client address that
//! login and admin events record.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use rs_keycloak_storage_postgres::{EventSettings, LoginSubject, NewLoginEvent, StorageError};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::oidc::{OidcState, digest};

tokio::task_local! {
    static CLIENT_ADDRESS: Option<String>;
}

/// Keeps the peer address of a request for the events it writes.
pub(crate) async fn remember_address(request: Request, next: Next) -> Response {
    let address = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| peer.ip().to_string());
    CLIENT_ADDRESS.scope(address, next.run(request)).await
}

/// The peer address of the request being served, if known.
pub(crate) fn client_address() -> Option<String> {
    CLIENT_ADDRESS.try_with(Clone::clone).ok().flatten()
}

/// The login event types the reference stores when a realm names none,
/// `EventType` values with `saveByDefault`, in the reference's order.
#[rustfmt::skip]
pub(crate) const DEFAULT_EVENT_TYPES: [&str; 102] = [
    "LOGIN", "LOGIN_ERROR", "REGISTER", "REGISTER_ERROR", "LOGOUT", "LOGOUT_ERROR",
    "CODE_TO_TOKEN", "CODE_TO_TOKEN_ERROR", "CLIENT_LOGIN", "CLIENT_LOGIN_ERROR",
    "FEDERATED_IDENTITY_LINK", "FEDERATED_IDENTITY_LINK_ERROR", "REMOVE_FEDERATED_IDENTITY",
    "REMOVE_FEDERATED_IDENTITY_ERROR", "UPDATE_EMAIL", "UPDATE_EMAIL_ERROR", "UPDATE_PROFILE",
    "UPDATE_PROFILE_ERROR", "UPDATE_PASSWORD", "UPDATE_PASSWORD_ERROR", "UPDATE_TOTP",
    "UPDATE_TOTP_ERROR", "VERIFY_EMAIL", "VERIFY_EMAIL_ERROR", "VERIFY_PROFILE",
    "VERIFY_PROFILE_ERROR", "REMOVE_TOTP", "REMOVE_TOTP_ERROR", "GRANT_CONSENT",
    "GRANT_CONSENT_ERROR", "UPDATE_CONSENT", "UPDATE_CONSENT_ERROR", "REVOKE_GRANT",
    "REVOKE_GRANT_ERROR", "SEND_VERIFY_EMAIL", "SEND_VERIFY_EMAIL_ERROR", "SEND_RESET_PASSWORD",
    "SEND_RESET_PASSWORD_ERROR", "SEND_IDENTITY_PROVIDER_LINK",
    "SEND_IDENTITY_PROVIDER_LINK_ERROR", "RESET_PASSWORD", "RESET_PASSWORD_ERROR",
    "RESTART_AUTHENTICATION", "RESTART_AUTHENTICATION_ERROR", "IDENTITY_PROVIDER_LINK_ACCOUNT",
    "IDENTITY_PROVIDER_LINK_ACCOUNT_ERROR", "IDENTITY_PROVIDER_LOGIN",
    "IDENTITY_PROVIDER_LOGIN_ERROR", "IDENTITY_PROVIDER_FIRST_LOGIN",
    "IDENTITY_PROVIDER_FIRST_LOGIN_ERROR", "IDENTITY_PROVIDER_POST_LOGIN",
    "IDENTITY_PROVIDER_POST_LOGIN_ERROR", "IMPERSONATE", "IMPERSONATE_ERROR",
    "CUSTOM_REQUIRED_ACTION", "CUSTOM_REQUIRED_ACTION_ERROR", "EXECUTE_ACTIONS",
    "EXECUTE_ACTIONS_ERROR", "EXECUTE_ACTION_TOKEN_ERROR", "CLIENT_REGISTER",
    "CLIENT_REGISTER_ERROR", "CLIENT_UPDATE", "CLIENT_UPDATE_ERROR", "CLIENT_DELETE",
    "CLIENT_DELETE_ERROR", "CLIENT_INITIATED_ACCOUNT_LINKING",
    "CLIENT_INITIATED_ACCOUNT_LINKING_ERROR", "TOKEN_EXCHANGE", "TOKEN_EXCHANGE_ERROR",
    "OAUTH2_DEVICE_AUTH", "OAUTH2_DEVICE_AUTH_ERROR", "OAUTH2_DEVICE_VERIFY_USER_CODE",
    "OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR", "OAUTH2_DEVICE_CODE_TO_TOKEN",
    "OAUTH2_DEVICE_CODE_TO_TOKEN_ERROR", "AUTHREQID_TO_TOKEN", "AUTHREQID_TO_TOKEN_ERROR",
    "PERMISSION_TOKEN", "DELETE_ACCOUNT", "DELETE_ACCOUNT_ERROR",
    "USER_DISABLED_BY_PERMANENT_LOCKOUT", "USER_DISABLED_BY_TEMPORARY_LOCKOUT",
    "OAUTH2_EXTENSION_GRANT", "OAUTH2_EXTENSION_GRANT_ERROR", "FEDERATED_IDENTITY_OVERRIDE_LINK",
    "FEDERATED_IDENTITY_OVERRIDE_LINK_ERROR", "UPDATE_CREDENTIAL", "UPDATE_CREDENTIAL_ERROR",
    "REMOVE_CREDENTIAL", "REMOVE_CREDENTIAL_ERROR", "INVITE_ORG", "INVITE_ORG_ERROR",
    "VERIFIABLE_CREDENTIAL_REQUEST", "VERIFIABLE_CREDENTIAL_REQUEST_ERROR",
    "VERIFIABLE_CREDENTIAL_OFFER_REQUEST", "VERIFIABLE_CREDENTIAL_OFFER_REQUEST_ERROR",
    "VERIFIABLE_CREDENTIAL_CREATE_OFFER", "VERIFIABLE_CREDENTIAL_CREATE_OFFER_ERROR",
    "VERIFIABLE_CREDENTIAL_PRE_AUTHORIZED_GRANT",
    "VERIFIABLE_CREDENTIAL_PRE_AUTHORIZED_GRANT_ERROR", "JWT_AUTHORIZATION_GRANT",
    "JWT_AUTHORIZATION_GRANT_ERROR",
];

/// Whether a realm stores login events of this type.
fn stores(settings: &EventSettings, event_type: &str) -> bool {
    settings.events_enabled
        && if settings.enabled_event_types.is_empty() {
            DEFAULT_EVENT_TYPES.contains(&event_type)
        } else {
            settings
                .enabled_event_types
                .iter()
                .any(|kind| kind == event_type)
        }
}

/// The `code_id` of an event before a user session exists. The reference
/// names its authentication session; this server names a digest of the
/// authorization request instead of the request id, which binds the form.
fn request_code_id(request_id: &str) -> String {
    digest(request_id)
        .iter()
        .take(12)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Stores one login event of a realm with these settings.
async fn record(
    s: &OidcState,
    realm_id: &str,
    settings: &EventSettings,
    event_type: &str,
    fields: EventFields,
    details: Map<String, Value>,
) -> Result<(), StorageError> {
    let address = client_address();
    s.storage
        .record_login_event(
            &NewLoginEvent {
                id: &Uuid::new_v4().to_string(),
                realm_id,
                event_type,
                client_id: fields.client_id.as_deref(),
                user_id: fields.user_id.as_deref(),
                session_id: fields.session_id.as_deref(),
                ip_address: address.as_deref(),
                error: fields.error,
                details: &Value::Object(details).to_string(),
            },
            settings.events_expiration,
        )
        .await
}

/// The columns of an event besides its type, realm and address.
#[derive(Default)]
struct EventFields {
    client_id: Option<String>,
    user_id: Option<String>,
    session_id: Option<String>,
    error: Option<&'static str>,
}

/// Records a refused password sign-in as `LOGIN_ERROR`, with the error the
/// reference's `UsernamePasswordForm` names: `user_not_found`,
/// `user_disabled`, `user_temporarily_disabled` or
/// `invalid_user_credentials`.
pub(crate) async fn login_error(
    s: &OidcState,
    realm_id: &str,
    request_id: &str,
    username: &str,
) -> Result<(), StorageError> {
    let Some(settings) = s.storage.event_settings(realm_id).await? else {
        return Ok(());
    };
    if !stores(&settings, "LOGIN_ERROR") {
        return Ok(());
    }
    let subject = s
        .storage
        .login_subject(realm_id, &username.to_lowercase())
        .await?;
    let summary = s.storage.authorization_request_summary(request_id).await?;
    let (user_id, error) = match subject {
        LoginSubject::Unknown => (None, "user_not_found"),
        LoginSubject::User { id, enabled, .. } if !enabled => (Some(id), "user_disabled"),
        LoginSubject::User { id, locked, .. } if locked => (Some(id), "user_temporarily_disabled"),
        LoginSubject::User { id, .. } => (Some(id), "invalid_user_credentials"),
    };
    let mut details = Map::new();
    details.insert("auth_method".into(), json!("openid-connect"));
    details.insert("auth_type".into(), json!("code"));
    if let Some(summary) = &summary {
        details.insert("redirect_uri".into(), json!(summary.redirect_uri));
    }
    details.insert("code_id".into(), json!(request_code_id(request_id)));
    details.insert("username".into(), json!(username));
    let fields = EventFields {
        client_id: summary.map(|summary| summary.client_identifier),
        user_id,
        error: Some(error),
        ..EventFields::default()
    };
    record(s, realm_id, &settings, "LOGIN_ERROR", fields, details).await
}

/// Records `LOGIN` when a sign-in ends in an authorization code, with the
/// details the reference's `AuthenticationManager` adds. Call it before the
/// code consumes the request.
pub(crate) async fn login(
    s: &OidcState,
    realm_id: &str,
    request_id: &str,
    session_id: &str,
    consent_granted: bool,
) -> Result<(), StorageError> {
    let Some(settings) = s.storage.event_settings(realm_id).await? else {
        return Ok(());
    };
    if !stores(&settings, "LOGIN") {
        return Ok(());
    }
    let Some(summary) = s.storage.authorization_request_summary(request_id).await? else {
        return Ok(());
    };
    let user = s.storage.session_user(realm_id, session_id).await?;
    let consent = if consent_granted {
        "consent_granted"
    } else if summary.consent_required {
        "persistent_consent"
    } else {
        "no_consent_required"
    };
    let mut details = Map::new();
    details.insert("auth_method".into(), json!("openid-connect"));
    details.insert("auth_type".into(), json!("code"));
    details.insert("response_type".into(), json!("code"));
    details.insert("redirect_uri".into(), json!(summary.redirect_uri));
    details.insert("consent".into(), json!(consent));
    details.insert("code_id".into(), json!(session_id));
    let (user_id, username) = user.unzip();
    if let Some(username) = username {
        details.insert("username".into(), json!(username));
    }
    details.insert("response_mode".into(), json!(summary.response_mode));
    let fields = EventFields {
        client_id: Some(summary.client_identifier),
        user_id,
        session_id: Some(session_id.to_owned()),
        error: None,
    };
    record(s, realm_id, &settings, "LOGIN", fields, details).await
}
