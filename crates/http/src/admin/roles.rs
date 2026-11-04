//! Admin REST routes for realm roles and user realm role mappings.
//!
//! Follows the recorded cases in `tests/reference/admin-role-observations.json`.
//! Composite editing, role attributes and client roles are not modelled and
//! are refused.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rs_keycloak_storage_postgres::{RoleCreation, RoleDeletion, RoleMappingChange, RoleRecord};
use serde_json::{Value, json};
use uuid::Uuid;

use super::users::{
    json_object, json_response, realm_id, representation as user_representation, unparsable,
};
use super::{AdminError, authorize};
use crate::oidc::OidcState;

/// Characters escaped in a role name path segment; RFC 3986 unreserved
/// characters stay as they are.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub(super) fn routes() -> Router<OidcState> {
    Router::new()
        .route(
            "/admin/realms/{realm}/roles",
            get(list_roles).post(create_role),
        )
        .route(
            "/admin/realms/{realm}/roles/{role}",
            get(read_role).delete(delete_role),
        )
        .route("/admin/realms/{realm}/roles/{role}/users", get(role_users))
        .route(
            "/admin/realms/{realm}/users/{user}/role-mappings/realm",
            get(user_roles)
                .post(add_user_roles)
                .delete(remove_user_roles),
        )
}

fn role_not_found() -> AdminError {
    AdminError::Error(StatusCode::NOT_FOUND, "Could not find role".into())
}

fn representation(role: &RoleRecord, realm_id: &str) -> Value {
    let mut fields = json!({
        "id": role.id,
        "name": role.name,
        "composite": role.composite,
        "clientRole": false,
        "containerId": realm_id,
    });
    if let Some(description) = &role.description {
        fields["description"] = json!(description);
    }
    fields
}

async fn list_roles(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let roles = state.storage.roles(&realm_id).await?;
    Ok(json_response(Value::Array(
        roles
            .iter()
            .map(|role| representation(role, &realm_id))
            .collect(),
    )))
}

async fn create_role(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AdminError> {
    let actor = authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let fields = json_object(&body)?;
    if let Some(field) = fields.keys().find(|key| {
        !matches!(
            key.as_str(),
            "name" | "description" | "composite" | "clientRole"
        )
    }) {
        return Err(AdminError::bad_request(format!(
            "Unsupported role field: {field}"
        )));
    }
    for flag in ["composite", "clientRole"] {
        match fields.get(flag) {
            None | Some(Value::Null | Value::Bool(false)) => (),
            Some(Value::Bool(true)) => {
                return Err(AdminError::bad_request(format!(
                    "Unsupported role setting: {flag}"
                )));
            }
            Some(_) => return Err(unparsable()),
        }
    }
    let name = match fields.get("name") {
        None | Some(Value::Null) => None,
        Some(Value::String(name)) => Some(name.trim()).filter(|name| !name.is_empty()),
        Some(_) => return Err(unparsable()),
    }
    .ok_or_else(|| AdminError::Error(StatusCode::BAD_REQUEST, "role has no name".into()))?;
    if name.len() > 255 || name.contains(['/', '\\']) || name.contains(char::is_control) {
        return Err(AdminError::bad_request("Invalid role name"));
    }
    let description = match fields.get("description") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if text.len() <= 255 => Some(text.as_str()),
        Some(Value::String(_)) => return Err(AdminError::bad_request("Invalid role description")),
        Some(_) => return Err(unparsable()),
    };
    match state
        .storage
        .create_role(
            &realm_id,
            &Uuid::new_v4().to_string(),
            name,
            description,
            &actor,
        )
        .await?
    {
        RoleCreation::Created => {
            let location = format!(
                "{}/admin/realms/{realm}/roles/{}",
                state.issuer_base.trim_end_matches('/'),
                utf8_percent_encode(name, SEGMENT)
            );
            let location = HeaderValue::from_str(&location).map_err(|_| AdminError::Unavailable)?;
            Ok((StatusCode::CREATED, [(header::LOCATION, location)]).into_response())
        }
        RoleCreation::Exists => Err(AdminError::Message(
            StatusCode::CONFLICT,
            format!("Role with name {name} already exists"),
        )),
    }
}

async fn find_role(
    state: &OidcState,
    realm_id: &str,
    name: &str,
) -> Result<RoleRecord, AdminError> {
    state
        .storage
        .role(realm_id, name)
        .await?
        .ok_or_else(role_not_found)
}

async fn read_role(
    State(state): State<OidcState>,
    Path((realm, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let role = find_role(&state, &realm_id, &name).await?;
    let mut fields = representation(&role, &realm_id);
    fields["attributes"] = json!({});
    Ok(json_response(fields))
}

async fn delete_role(
    State(state): State<OidcState>,
    Path((realm, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    match state.storage.delete_role(&realm_id, &name, &actor).await? {
        RoleDeletion::Deleted => Ok(StatusCode::NO_CONTENT),
        RoleDeletion::NotFound => Err(role_not_found()),
        RoleDeletion::DefaultRole => Err(AdminError::bad_request(
            "The default role of a realm cannot be removed",
        )),
    }
}

async fn role_users(
    State(state): State<OidcState>,
    Path((realm, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let role = find_role(&state, &realm_id, &name).await?;
    let users = state.storage.role_users(&realm_id, &role.id).await?;
    Ok(json_response(Value::Array(
        users.into_iter().map(user_representation).collect(),
    )))
}

async fn user_roles(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let roles = state
        .storage
        .user_roles(&realm_id, &user)
        .await?
        .ok_or_else(|| AdminError::Error(StatusCode::NOT_FOUND, "User not found".into()))?;
    Ok(json_response(Value::Array(
        roles
            .iter()
            .map(|role| representation(role, &realm_id))
            .collect(),
    )))
}

/// Parses a role list body into `(id, name)` pairs.
fn role_list(body: &[u8]) -> Result<Vec<(String, String)>, AdminError> {
    let Ok(Value::Array(items)) = serde_json::from_slice::<Value>(body) else {
        return Err(unparsable());
    };
    if items.len() > 100 {
        return Err(AdminError::bad_request("Too many roles"));
    }
    items
        .iter()
        .map(|item| match (item.get("id"), item.get("name")) {
            (Some(Value::String(id)), Some(Value::String(name))) => Ok((id.clone(), name.clone())),
            _ => Err(AdminError::Error(
                StatusCode::NOT_FOUND,
                "Role not found".into(),
            )),
        })
        .collect()
}

async fn change_user_roles(
    state: OidcState,
    realm: String,
    user: String,
    headers: HeaderMap,
    body: Bytes,
    grant: bool,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let roles = role_list(&body)?;
    match state
        .storage
        .change_user_roles(&realm_id, &user, &roles, grant, &actor)
        .await?
    {
        RoleMappingChange::Changed => Ok(StatusCode::NO_CONTENT),
        RoleMappingChange::UserNotFound => Err(AdminError::Error(
            StatusCode::NOT_FOUND,
            "User not found".into(),
        )),
        RoleMappingChange::RoleNotFound => Err(AdminError::Error(
            StatusCode::NOT_FOUND,
            "Role not found".into(),
        )),
    }
}

async fn add_user_roles(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    change_user_roles(state, realm, user, headers, body, true).await
}

async fn remove_user_roles(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    change_user_roles(state, realm, user, headers, body, false).await
}
