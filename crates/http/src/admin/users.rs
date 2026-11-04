//! Admin REST routes for users within a realm.
//!
//! Follows the recorded cases in `tests/reference/admin-user-observations.json`.
//! Usernames and emails are stored lowercased, as the reference does. Fields
//! and search parameters that are not modelled yet are refused.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use rs_keycloak_storage_postgres::{NewUser, UserCreation, UserRecord, UsernameFilter};
use serde_json::{Map, Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{AdminError, authorize};
use crate::oidc::OidcState;

/// Keycloak's default page size for user searches.
const DEFAULT_MAX_RESULTS: i64 = 100;
/// Longest password the login path accepts.
const MAX_PASSWORD_BYTES: usize = 1024;

pub(super) fn routes() -> Router<OidcState> {
    Router::new()
        .route(
            "/admin/realms/{realm}/users",
            post(create_user).get(search_users),
        )
        .route("/admin/realms/{realm}/users/count", get(count_users))
        .route(
            "/admin/realms/{realm}/users/{user}",
            get(read_user).delete(delete_user),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/reset-password",
            put(reset_password),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/consents",
            get(list_consents),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/credentials",
            get(list_credentials),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/credentials/{credential}",
            delete(delete_credential),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/consents/{client}",
            delete(revoke_consent),
        )
}

fn user_not_found() -> AdminError {
    AdminError::Error(StatusCode::NOT_FOUND, "User not found".into())
}

pub(super) fn unparsable() -> AdminError {
    AdminError::OAuth(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Cannot parse the JSON",
    )
}

/// Resolves the realm identifier for an existing realm name.
pub(super) async fn realm_id(state: &OidcState, name: &str) -> Result<String, AdminError> {
    state
        .storage
        .realm_by_name(name)
        .await?
        .map(|realm| realm.id)
        .ok_or(AdminError::RealmNotFound)
}

/// Parses a JSON object body or reports the reference parse error.
pub(super) fn json_object(body: &[u8]) -> Result<Map<String, Value>, AdminError> {
    match serde_json::from_slice(body) {
        Ok(Value::Object(fields)) => Ok(fields),
        _ => Err(unparsable()),
    }
}

/// Reads an optional string field, lowercased if requested.
fn text(fields: &Map<String, Value>, name: &str) -> Result<Option<String>, AdminError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.trim().is_empty() => Ok(None),
        Some(Value::String(value)) if value.len() <= 255 && !value.contains(char::is_control) => {
            Ok(Some(value.trim().to_owned()))
        }
        Some(Value::String(_)) => Err(AdminError::bad_request(format!("Invalid {name}"))),
        Some(_) => Err(unparsable()),
    }
}

fn flag(fields: &Map<String, Value>, name: &str) -> Result<bool, AdminError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(unparsable()),
    }
}

pub(super) fn representation(user: UserRecord) -> Value {
    let mut fields = Map::new();
    fields.insert("id".into(), json!(user.id));
    fields.insert("username".into(), json!(user.username));
    if let Some(first_name) = user.first_name {
        fields.insert("firstName".into(), json!(first_name));
    }
    if let Some(last_name) = user.last_name {
        fields.insert("lastName".into(), json!(last_name));
    }
    if let Some(email) = user.email {
        fields.insert("email".into(), json!(email));
    }
    fields.insert("emailVerified".into(), json!(user.email_verified));
    fields.insert("createdTimestamp".into(), json!(user.created_timestamp));
    fields.insert("enabled".into(), json!(user.enabled));
    fields.insert("totp".into(), json!(user.totp));
    fields.insert(
        "disableableCredentialTypes".into(),
        json!(if user.totp { vec!["otp"] } else { Vec::new() }),
    );
    fields.insert("requiredActions".into(), json!(user.required_actions));
    fields.insert("notBefore".into(), json!(0));
    Value::Object(fields)
}

pub(super) fn json_response(value: Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json;charset=UTF-8")],
        value.to_string(),
    )
        .into_response()
}

async fn create_user(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AdminError> {
    let actor = authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let fields = json_object(&body)?;
    const SUPPORTED: [&str; 7] = [
        "requiredActions",
        "username",
        "enabled",
        "email",
        "emailVerified",
        "firstName",
        "lastName",
    ];
    if let Some(field) = fields.keys().find(|key| !SUPPORTED.contains(&key.as_str())) {
        return Err(AdminError::bad_request(format!(
            "Unsupported user field: {field}"
        )));
    }
    let username = text(&fields, "username")?
        .ok_or_else(|| AdminError::bad_request("User name is missing"))?
        .to_lowercase();
    let email = text(&fields, "email")?.map(|email| email.to_lowercase());
    let first_name = text(&fields, "firstName")?;
    let last_name = text(&fields, "lastName")?;
    let required_actions = match fields.get("requiredActions") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(actions)) => actions
            .iter()
            .map(|action| match action {
                Value::String(action) if action == "CONFIGURE_TOTP" => Ok(action.clone()),
                Value::String(action) => Err(AdminError::bad_request(format!(
                    "Unsupported required action: {action}"
                ))),
                _ => Err(unparsable()),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(unparsable()),
    };
    let user_id = Uuid::new_v4().to_string();
    let user = NewUser {
        required_actions: &required_actions,
        username: &username,
        email: email.as_deref(),
        email_verified: flag(&fields, "emailVerified")?,
        first_name: first_name.as_deref(),
        last_name: last_name.as_deref(),
        enabled: flag(&fields, "enabled")?,
    };
    match state
        .storage
        .create_user(&realm_id, &user_id, &user, &actor)
        .await?
    {
        UserCreation::Created => {
            let location = format!(
                "{}/admin/realms/{realm}/users/{user_id}",
                state.issuer_base.trim_end_matches('/')
            );
            let location = HeaderValue::from_str(&location).map_err(|_| AdminError::Unavailable)?;
            Ok((StatusCode::CREATED, [(header::LOCATION, location)]).into_response())
        }
        UserCreation::UsernameExists => Err(AdminError::Message(
            StatusCode::CONFLICT,
            "User exists with same username".into(),
        )),
        UserCreation::EmailExists => Err(AdminError::Message(
            StatusCode::CONFLICT,
            "User exists with same email".into(),
        )),
    }
}

async fn search_users(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    if let Some(name) = params.keys().find(|name| {
        !matches!(
            name.as_str(),
            "username" | "exact" | "first" | "max" | "briefRepresentation"
        )
    }) {
        return Err(AdminError::bad_request(format!(
            "Unsupported user search parameter: {name}"
        )));
    }
    let number = |name: &str, default: i64| match params.get(name) {
        None => Ok(default),
        Some(value) => value
            .parse::<i64>()
            .ok()
            .filter(|value| *value >= 0)
            .ok_or_else(|| AdminError::bad_request(format!("Invalid {name}"))),
    };
    let first = number("first", 0)?;
    let max = number("max", DEFAULT_MAX_RESULTS)?.min(DEFAULT_MAX_RESULTS * 10);
    let username = params.get("username").map(|value| value.to_lowercase());
    let filter = match (&username, params.get("exact").map(String::as_str)) {
        (None, _) => UsernameFilter::Any,
        (Some(value), Some("true")) => UsernameFilter::Exact(value),
        (Some(value), _) => UsernameFilter::Contains(value),
    };
    let users = state
        .storage
        .search_users(&realm_id, filter, first, max)
        .await?;
    Ok(json_response(Value::Array(
        users.into_iter().map(representation).collect(),
    )))
}

async fn count_users(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    Ok(json_response(json!(
        state.storage.count_users(&realm_id).await?
    )))
}

async fn read_user(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let user = state
        .storage
        .user(&realm_id, &user)
        .await?
        .ok_or_else(user_not_found)?;
    Ok(json_response(representation(user)))
}

async fn delete_user(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    if state.storage.delete_user(&realm_id, &user, &actor).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(user_not_found())
    }
}

async fn reset_password(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let fields = json_object(&body)?;
    if let Some(field) = fields
        .keys()
        .find(|key| !matches!(key.as_str(), "type" | "value" | "temporary"))
    {
        return Err(AdminError::bad_request(format!(
            "Unsupported credential field: {field}"
        )));
    }
    match fields.get("type") {
        None | Some(Value::Null) => (),
        Some(Value::String(kind)) if kind == "password" => (),
        Some(_) => {
            return Err(AdminError::bad_request(
                "Only password credentials are supported",
            ));
        }
    }
    if flag(&fields, "temporary")? {
        return Err(AdminError::bad_request(
            "Temporary passwords are not supported",
        ));
    }
    let password = match fields.get("value") {
        Some(Value::String(value)) if !value.is_empty() => Zeroizing::new(value.clone()),
        None | Some(Value::Null | Value::String(_)) => {
            return Err(AdminError::Error(
                StatusCode::BAD_REQUEST,
                "Empty password not allowed".into(),
            ));
        }
        Some(_) => return Err(unparsable()),
    };
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(AdminError::bad_request(
            "Password must be at most 1024 bytes",
        ));
    }
    // Check the user before spending hashing work on an unknown identifier.
    if state.storage.user(&realm_id, &user).await?.is_none() {
        return Err(user_not_found());
    }
    let permit = Arc::clone(&state.hash_slots)
        .try_acquire_owned()
        .map_err(|_| AdminError::Unavailable)?;
    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        rs_keycloak_crypto::hash_password(password.as_bytes())
    })
    .await
    .map_err(|_| AdminError::Unavailable)?
    .map(Zeroizing::new)
    .map_err(|_| AdminError::Unavailable)?;
    let changed = state
        .storage
        .reset_password(
            &realm_id,
            &user,
            &Uuid::new_v4().to_string(),
            hash.as_bytes(),
            &actor,
        )
        .await?;
    if changed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(user_not_found())
    }
}

async fn list_consents(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let consents = state
        .storage
        .user_consents(&realm_id, &user)
        .await?
        .ok_or_else(user_not_found)?;
    let listed = consents
        .into_iter()
        .map(|consent| {
            json!({
                "clientId": consent.client_identifier,
                "grantedClientScopes": consent.scope.split(' ').filter(|scope| !scope.is_empty()).collect::<Vec<_>>(),
                "createdDate": consent.created,
                "lastUpdatedDate": consent.updated,
                "additionalGrants": [],
            })
        })
        .collect();
    Ok(json_response(Value::Array(listed)))
}

async fn revoke_consent(
    State(state): State<OidcState>,
    Path((realm, user, client)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    // The pinned UserResource reports an unknown client before the consent.
    if state
        .storage
        .clients(&realm_id, Some(&client))
        .await?
        .is_empty()
    {
        return Err(AdminError::Error(
            StatusCode::NOT_FOUND,
            "Client not found".into(),
        ));
    }
    if state
        .storage
        .revoke_consent(&realm_id, &user, &client)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AdminError::Error(
            StatusCode::NOT_FOUND,
            "Consent nor offline token not found".into(),
        ))
    }
}

async fn list_credentials(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let credentials = state
        .storage
        .user_credentials(&realm_id, &user)
        .await?
        .ok_or_else(user_not_found)?;
    let listed = credentials
        .into_iter()
        .map(|credential| {
            // Secrets and seeds are never returned, only algorithm parameters.
            let data = if credential.credential_type == "otp" {
                json!({"subType":"totp","digits":6,"period":30,"algorithm":"HmacSHA1"})
            } else {
                json!({"algorithm":"argon2"})
            };
            let mut fields = json!({
                "id": credential.id,
                "type": credential.credential_type,
                "createdDate": credential.created,
                "credentialData": data.to_string(),
            });
            if let Some(label) = credential.user_label {
                fields["userLabel"] = json!(label);
            }
            fields
        })
        .collect();
    Ok(json_response(Value::Array(listed)))
}

async fn delete_credential(
    State(state): State<OidcState>,
    Path((realm, user, credential)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    if state
        .storage
        .delete_credential(&realm_id, &user, &credential)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AdminError::Error(
            StatusCode::NOT_FOUND,
            "Credential not found".into(),
        ))
    }
}
