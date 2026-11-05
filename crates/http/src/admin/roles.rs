//! Admin REST routes for realm and client roles and user and group role
//! mappings.
//!
//! Follows `tests/reference/admin-role-observations.json`,
//! `tests/reference/client-role-observations.json` and
//! `tests/reference/group-role-observations.json`. Realm roles live under
//! `/roles`, client roles under `/clients/{id}/roles`; both share these
//! handlers through a resolved container, and users and groups share the
//! role-mapping handlers through a role holder. Composites can be read; composite
//! editing and role attributes are not modelled and are refused.

use std::collections::HashMap;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rs_keycloak_storage_postgres::{
    RoleCreation, RoleDeletion, RoleHolder, RoleMappingChange, RoleRecord,
};
use serde_json::{Value, json};
use uuid::Uuid;

use super::users::{
    json_object, json_response, realm_id, representation as user_representation, unparsable,
};
use super::{Access, AdminError, authorize};
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
            "/admin/realms/{realm}/roles/{role}/composites",
            get(role_composites),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/roles",
            get(list_roles).post(create_role),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/roles/{role}",
            get(read_role).delete(delete_role),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/roles/{role}/users",
            get(role_users),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/roles/{role}/composites",
            get(role_composites),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/role-mappings/realm",
            get(holder_roles)
                .post(add_holder_roles)
                .delete(remove_holder_roles),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/role-mappings/clients/{client}",
            get(holder_roles)
                .post(add_holder_roles)
                .delete(remove_holder_roles),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/role-mappings/realm/composite",
            get(effective_user_roles),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/role-mappings/clients/{client}/composite",
            get(effective_user_roles),
        )
        .route(
            "/admin/realms/{realm}/groups/{group}/role-mappings/realm",
            get(holder_roles)
                .post(add_holder_roles)
                .delete(remove_holder_roles),
        )
        .route(
            "/admin/realms/{realm}/groups/{group}/role-mappings/clients/{client}",
            get(holder_roles)
                .post(add_holder_roles)
                .delete(remove_holder_roles),
        )
}

/// Path parameters shared by the realm and client role routes.
type Params = Path<HashMap<String, String>>;

/// Where roles live: the realm, or one of its clients.
struct Container {
    realm_id: String,
    /// Internal client identifier for client roles.
    client: Option<String>,
}

fn param<'a>(params: &'a HashMap<String, String>, name: &str) -> Result<&'a str, AdminError> {
    params
        .get(name)
        .map(String::as_str)
        .ok_or(AdminError::Unavailable)
}

/// Resolves the realm and, for client routes, the client.
async fn container(
    state: &OidcState,
    params: &HashMap<String, String>,
) -> Result<Container, AdminError> {
    let realm_id = realm_id(state, param(params, "realm")?).await?;
    let client = match params.get("client") {
        None => None,
        Some(client) => Some(
            state
                .storage
                .client(&realm_id, client)
                .await?
                .ok_or_else(|| {
                    AdminError::Error(StatusCode::NOT_FOUND, "Could not find client".into())
                })?
                .id,
        ),
    };
    Ok(Container { realm_id, client })
}

/// Client roles are managed with client access, realm roles with realm access.
fn role_access(params: &HashMap<String, String>, client: Access, realm: Access) -> Access {
    if params.contains_key("client") {
        client
    } else {
        realm
    }
}

fn role_not_found() -> AdminError {
    AdminError::Error(StatusCode::NOT_FOUND, "Could not find role".into())
}

/// A role's representation; its container is its client, or else the realm.
fn representation(role: &RoleRecord, realm_id: &str) -> Value {
    let mut fields = json!({
        "id": role.id,
        "name": role.name,
        "composite": role.composite,
        "clientRole": role.client.is_some(),
        "containerId": role.client.as_deref().unwrap_or(realm_id),
    });
    if let Some(description) = &role.description {
        fields["description"] = json!(description);
    }
    fields
}

async fn list_roles(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(
        &state,
        &headers,
        param(&params, "realm")?,
        role_access(&params, Access::ViewClients, Access::ViewRealm),
    )
    .await?;
    let container = container(&state, &params).await?;
    let roles = state
        .storage
        .roles(&container.realm_id, container.client.as_deref())
        .await?;
    Ok(role_array(&roles, &container.realm_id))
}

async fn create_role(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AdminError> {
    let actor = authorize(
        &state,
        &headers,
        param(&params, "realm")?,
        role_access(&params, Access::ManageClients, Access::ManageRealm),
    )
    .await?;
    let container = container(&state, &params).await?;
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
    match fields.get("composite") {
        None | Some(Value::Null | Value::Bool(false)) => (),
        Some(Value::Bool(true)) => {
            return Err(AdminError::bad_request(
                "Unsupported role setting: composite",
            ));
        }
        Some(_) => return Err(unparsable()),
    }
    match fields.get("clientRole") {
        None | Some(Value::Null) => (),
        Some(Value::Bool(client_role)) if *client_role == container.client.is_some() => (),
        Some(_) => {
            return Err(AdminError::bad_request(
                "Unsupported role setting: clientRole",
            ));
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
            &container.realm_id,
            container.client.as_deref(),
            &Uuid::new_v4().to_string(),
            name,
            description,
            &actor,
        )
        .await?
    {
        RoleCreation::Created => {
            let realm = param(&params, "realm")?;
            let scope = match params.get("client") {
                Some(client) => format!("clients/{client}/roles"),
                None => "roles".to_owned(),
            };
            let location = format!(
                "{}/admin/realms/{realm}/{scope}/{}",
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
    container: &Container,
    name: &str,
) -> Result<RoleRecord, AdminError> {
    state
        .storage
        .role(&container.realm_id, container.client.as_deref(), name)
        .await?
        .ok_or_else(role_not_found)
}

async fn read_role(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(
        &state,
        &headers,
        param(&params, "realm")?,
        role_access(&params, Access::ViewClients, Access::ViewRealm),
    )
    .await?;
    let container = container(&state, &params).await?;
    let role = find_role(&state, &container, param(&params, "role")?).await?;
    let mut fields = representation(&role, &container.realm_id);
    fields["attributes"] = json!({});
    Ok(json_response(fields))
}

async fn role_composites(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(
        &state,
        &headers,
        param(&params, "realm")?,
        role_access(&params, Access::ViewClients, Access::ViewRealm),
    )
    .await?;
    let container = container(&state, &params).await?;
    let roles = state
        .storage
        .role_composites(
            &container.realm_id,
            container.client.as_deref(),
            param(&params, "role")?,
        )
        .await?
        .ok_or_else(role_not_found)?;
    Ok(role_array(&roles, &container.realm_id))
}

async fn delete_role(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(
        &state,
        &headers,
        param(&params, "realm")?,
        role_access(&params, Access::ManageClients, Access::ManageRealm),
    )
    .await?;
    let container = container(&state, &params).await?;
    match state
        .storage
        .delete_role(
            &container.realm_id,
            container.client.as_deref(),
            param(&params, "role")?,
            &actor,
        )
        .await?
    {
        RoleDeletion::Deleted => Ok(StatusCode::NO_CONTENT),
        RoleDeletion::NotFound => Err(role_not_found()),
        RoleDeletion::DefaultRole => Err(AdminError::bad_request(
            "The default role of a realm cannot be removed",
        )),
    }
}

async fn role_users(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(
        &state,
        &headers,
        param(&params, "realm")?,
        Access::ViewUsers,
    )
    .await?;
    let container = container(&state, &params).await?;
    let role = find_role(&state, &container, param(&params, "role")?).await?;
    let users = state
        .storage
        .role_users(&container.realm_id, &role.id)
        .await?;
    Ok(json_response(Value::Array(
        users.into_iter().map(user_representation).collect(),
    )))
}

/// The user or group a role-mapping route names, with the error for a
/// missing one.
fn holder(params: &HashMap<String, String>) -> Result<(RoleHolder<'_>, AdminError), AdminError> {
    match (params.get("user"), params.get("group")) {
        (Some(user), None) => Ok((
            RoleHolder::User(user),
            AdminError::Error(StatusCode::NOT_FOUND, "User not found".into()),
        )),
        (None, Some(group)) => Ok((
            RoleHolder::Group(group),
            AdminError::Error(StatusCode::NOT_FOUND, "Could not find group by id".into()),
        )),
        _ => Err(AdminError::Unavailable),
    }
}

fn role_array(roles: &[RoleRecord], realm_id: &str) -> Response {
    json_response(Value::Array(
        roles
            .iter()
            .map(|role| representation(role, realm_id))
            .collect(),
    ))
}

async fn holder_roles(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(
        &state,
        &headers,
        param(&params, "realm")?,
        Access::ViewUsers,
    )
    .await?;
    let container = container(&state, &params).await?;
    let (holder, not_found) = holder(&params)?;
    let roles = state
        .storage
        .holder_roles(&container.realm_id, container.client.as_deref(), holder)
        .await?
        .ok_or(not_found)?;
    Ok(role_array(&roles, &container.realm_id))
}

/// A user's effective roles in one container, including those of groups.
async fn effective_user_roles(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(
        &state,
        &headers,
        param(&params, "realm")?,
        Access::ViewUsers,
    )
    .await?;
    let container = container(&state, &params).await?;
    let roles = state
        .storage
        .effective_role_records(
            &container.realm_id,
            container.client.as_deref(),
            param(&params, "user")?,
        )
        .await?
        .ok_or_else(|| AdminError::Error(StatusCode::NOT_FOUND, "User not found".into()))?;
    Ok(role_array(&roles, &container.realm_id))
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

async fn change_holder_roles(
    state: OidcState,
    params: HashMap<String, String>,
    headers: HeaderMap,
    body: Bytes,
    grant: bool,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(
        &state,
        &headers,
        param(&params, "realm")?,
        Access::ManageUsers,
    )
    .await?;
    let container = container(&state, &params).await?;
    let (holder, not_found) = holder(&params)?;
    let roles = role_list(&body)?;
    match state
        .storage
        .change_holder_roles(
            &container.realm_id,
            container.client.as_deref(),
            holder,
            &roles,
            grant,
            &actor,
        )
        .await?
    {
        RoleMappingChange::Changed => Ok(StatusCode::NO_CONTENT),
        RoleMappingChange::HolderNotFound => Err(not_found),
        RoleMappingChange::RoleNotFound => Err(AdminError::Error(
            StatusCode::NOT_FOUND,
            "Role not found".into(),
        )),
    }
}

async fn add_holder_roles(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    change_holder_roles(state, params, headers, body, true).await
}

async fn remove_holder_roles(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    change_holder_roles(state, params, headers, body, false).await
}
