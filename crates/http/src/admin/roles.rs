//! Admin REST routes for realm and client roles and user and group role
//! mappings.
//!
//! Follows `tests/reference/admin-role-observations.json`,
//! `tests/reference/client-role-observations.json` and
//! `tests/reference/group-role-observations.json`. Realm roles live under
//! `/roles`, client roles under `/clients/{id}/roles`; both share these
//! handlers through a resolved container, and users and groups share the
//! role-mapping handlers through a role holder. Composites follow
//! `tests/reference/role-composite-observations.json`; role attributes are
//! not modelled and are refused.

use std::collections::HashMap;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rs_keycloak_storage_postgres::{
    CompositeChange, NewRole, RoleCreation, RoleDeletion, RoleHolder, RoleMappingChange, RoleNames,
    RoleRecord, RoleUpdate,
};
use serde_json::{Map, Value, json};
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
            get(read_role).put(update_role).delete(delete_role),
        )
        .route("/admin/realms/{realm}/roles/{role}/users", get(role_users))
        .route(
            "/admin/realms/{realm}/roles-by-id/{id}",
            get(read_role_by_id)
                .put(update_role_by_id)
                .delete(delete_role_by_id),
        )
        .route(
            "/admin/realms/{realm}/roles-by-id/{id}/composites",
            get(composites_by_id)
                .post(add_composites_by_id)
                .delete(remove_composites_by_id),
        )
        .route(
            "/admin/realms/{realm}/roles/{role}/composites",
            get(role_composites)
                .post(add_composites)
                .delete(remove_composites),
        )
        .route(
            "/admin/realms/{realm}/roles/{role}/composites/realm",
            get(realm_composites),
        )
        .route(
            "/admin/realms/{realm}/roles/{role}/composites/clients/{child_client}",
            get(client_composites),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/roles",
            get(list_roles).post(create_role),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/roles/{role}",
            get(read_role).put(update_role).delete(delete_role),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/roles/{role}/users",
            get(role_users),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/roles/{role}/composites",
            get(role_composites)
                .post(add_composites)
                .delete(remove_composites),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/roles/{role}/composites/realm",
            get(realm_composites),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/roles/{role}/composites/clients/{child_client}",
            get(client_composites),
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
            "/admin/realms/{realm}/users/{user}/role-mappings",
            get(all_mappings),
        )
        .route(
            "/admin/realms/{realm}/groups/{group}/role-mappings",
            get(all_mappings),
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

/// Reads a role body's required name and optional description.
fn name_and_description(fields: &Map<String, Value>) -> Result<(&str, Option<&str>), AdminError> {
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
    Ok((name, description))
}

/// Replaces a role's name and description. Read-only fields of the
/// representation that admin clients send back are accepted and ignored.
async fn update_role(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
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
            "id" | "name"
                | "description"
                | "composite"
                | "clientRole"
                | "containerId"
                | "attributes"
        )
    }) {
        return Err(AdminError::bad_request(format!(
            "Unsupported role field: {field}"
        )));
    }
    if !matches!(fields.get("attributes"), None | Some(Value::Null))
        && fields.get("attributes") != Some(&json!({}))
    {
        return Err(AdminError::bad_request(
            "Unsupported role field: attributes",
        ));
    }
    let (name, description) = name_and_description(&fields)?;
    match state
        .storage
        .update_role(
            &container.realm_id,
            container.client.as_deref(),
            param(&params, "role")?,
            name,
            description,
            &actor,
        )
        .await?
    {
        RoleUpdate::Updated => Ok(StatusCode::NO_CONTENT),
        RoleUpdate::NotFound => Err(role_not_found()),
        RoleUpdate::Exists => Err(AdminError::OAuth(
            StatusCode::CONFLICT,
            "conflict",
            "Duplicate resource error",
        )),
    }
}

/// Resolves `/roles-by-id/{id}` to the name-based parameters of the role's
/// own container, so by-id routes share the name-based handlers, which then
/// check the access that container needs. Only an admin of the realm may
/// learn whether an identifier exists.
async fn by_id(
    state: &OidcState,
    headers: &HeaderMap,
    mut params: HashMap<String, String>,
) -> Result<HashMap<String, String>, AdminError> {
    authorize(state, headers, param(&params, "realm")?, Access::AnyRole).await?;
    let realm_id = realm_id(state, param(&params, "realm")?).await?;
    let role = state
        .storage
        .role_by_id(&realm_id, param(&params, "id")?)
        .await?
        .ok_or_else(|| {
            AdminError::Error(StatusCode::NOT_FOUND, "Could not find role with id".into())
        })?;
    params.insert("role".into(), role.name);
    if let Some(client) = role.client {
        params.insert("client".into(), client);
    }
    Ok(params)
}

async fn read_role_by_id(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    let params = by_id(&state, &headers, params).await?;
    read_role(State(state), Path(params), headers).await
}

async fn update_role_by_id(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    let params = by_id(&state, &headers, params).await?;
    update_role(State(state), Path(params), headers, body).await
}

async fn delete_role_by_id(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let params = by_id(&state, &headers, params).await?;
    delete_role(State(state), Path(params), headers).await
}

async fn composites_by_id(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    let params = by_id(&state, &headers, params).await?;
    list_composites(state, params, headers, Children::All).await
}

async fn add_composites_by_id(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    let params = by_id(&state, &headers, params).await?;
    change_composites(state, params, headers, body, true).await
}

async fn remove_composites_by_id(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    let params = by_id(&state, &headers, params).await?;
    change_composites(state, params, headers, body, false).await
}

fn composite_not_found() -> AdminError {
    AdminError::Error(
        StatusCode::NOT_FOUND,
        "Could not find composite role".into(),
    )
}

/// Parses a creation body's `composites`: realm role names under `realm`,
/// and client role names by public client identifier under `client`. Each
/// name is kept once.
fn requested_composites(value: Option<&Value>) -> Result<RoleNames, AdminError> {
    let names = |value: &Value| -> Result<Vec<String>, AdminError> {
        let Value::Array(items) = value else {
            return Err(unparsable());
        };
        let mut names = items
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or_else(unparsable))
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        names.dedup();
        Ok(names)
    };
    let mut composites = RoleNames::default();
    let fields = match value {
        None | Some(Value::Null) => return Ok(composites),
        Some(Value::Object(fields)) => fields,
        Some(_) => return Err(unparsable()),
    };
    for (key, value) in fields {
        match (key.as_str(), value) {
            (_, Value::Null) => (),
            ("realm", value) => composites.realm = names(value)?,
            ("client", Value::Object(clients)) => {
                for (client, value) in clients {
                    composites.clients.insert(client.clone(), names(value)?);
                }
            }
            _ => {
                return Err(AdminError::bad_request(format!(
                    "Unsupported role composites field: {key}"
                )));
            }
        }
    }
    Ok(composites)
}

fn role_not_found() -> AdminError {
    AdminError::Error(StatusCode::NOT_FOUND, "Could not find role".into())
}

/// A role's representation; its container is its client, or else the realm.
pub(super) fn representation(role: &RoleRecord, realm_id: &str) -> Value {
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
            "name" | "description" | "composite" | "clientRole" | "composites"
        )
    }) {
        return Err(AdminError::bad_request(format!(
            "Unsupported role field: {field}"
        )));
    }
    // The reference derives `composite` from `composites`.
    if !matches!(
        fields.get("composite"),
        None | Some(Value::Null | Value::Bool(_))
    ) {
        return Err(unparsable());
    }
    let composites = requested_composites(fields.get("composites"))?;
    match fields.get("clientRole") {
        None | Some(Value::Null) => (),
        Some(Value::Bool(client_role)) if *client_role == container.client.is_some() => (),
        Some(_) => {
            return Err(AdminError::bad_request(
                "Unsupported role setting: clientRole",
            ));
        }
    }
    let (name, description) = name_and_description(&fields)?;
    match state
        .storage
        .create_role(
            &container.realm_id,
            container.client.as_deref(),
            &NewRole {
                id: &Uuid::new_v4().to_string(),
                name,
                description,
                composites: &composites,
            },
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
        RoleCreation::CompositeNotFound => Err(composite_not_found()),
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

/// Which children a composite listing shows.
enum Children {
    All,
    Realm,
    /// Roles of the client named by the `child_client` path parameter.
    Client,
}

async fn list_composites(
    state: OidcState,
    params: HashMap<String, String>,
    headers: HeaderMap,
    children: Children,
) -> Result<Response, AdminError> {
    authorize(
        &state,
        &headers,
        param(&params, "realm")?,
        role_access(&params, Access::ViewClients, Access::ViewRealm),
    )
    .await?;
    let container = container(&state, &params).await?;
    let child_client = match children {
        Children::Client => Some(
            state
                .storage
                .client(&container.realm_id, param(&params, "child_client")?)
                .await?
                .ok_or_else(|| {
                    AdminError::Error(StatusCode::NOT_FOUND, "Could not find client".into())
                })?
                .id,
        ),
        Children::All | Children::Realm => None,
    };
    let mut roles = state
        .storage
        .role_composites(
            &container.realm_id,
            container.client.as_deref(),
            param(&params, "role")?,
        )
        .await?
        .ok_or_else(role_not_found)?;
    match children {
        Children::All => (),
        Children::Realm => roles.retain(|role| role.client.is_none()),
        Children::Client => roles.retain(|role| role.client == child_client),
    }
    Ok(role_array(&roles, &container.realm_id))
}

async fn role_composites(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    list_composites(state, params, headers, Children::All).await
}

async fn realm_composites(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    list_composites(state, params, headers, Children::Realm).await
}

async fn client_composites(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    list_composites(state, params, headers, Children::Client).await
}

async fn change_composites(
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
        role_access(&params, Access::ManageClients, Access::ManageRealm),
    )
    .await?;
    let container = container(&state, &params).await?;
    let children = role_list(&body).map_err(|error| match error {
        RoleListError::Malformed => AdminError::OAuth(
            StatusCode::BAD_REQUEST,
            "unknown_error",
            "Cannot parse the JSON",
        ),
        RoleListError::Incomplete => composite_not_found(),
        RoleListError::TooMany => AdminError::bad_request("Too many roles"),
    })?;
    match state
        .storage
        .change_composites(
            &container.realm_id,
            container.client.as_deref(),
            param(&params, "role")?,
            &children,
            grant,
            &actor,
        )
        .await?
    {
        CompositeChange::Changed => Ok(StatusCode::NO_CONTENT),
        CompositeChange::RoleNotFound => Err(role_not_found()),
        CompositeChange::ChildNotFound => Err(composite_not_found()),
    }
}

async fn add_composites(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    change_composites(state, params, headers, body, true).await
}

async fn remove_composites(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    change_composites(state, params, headers, body, false).await
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

/// A holder's realm and client mappings together; empty parts are left
/// out, and client mappings are keyed by public client identifier.
async fn all_mappings(
    State(state): State<OidcState>,
    Path(params): Params,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    let realm = param(&params, "realm")?;
    authorize(&state, &headers, realm, Access::ViewUsers).await?;
    let realm_id = realm_id(&state, realm).await?;
    let (holder, not_found) = holder(&params)?;
    let mappings = state
        .storage
        .holder_mappings(&realm_id, holder)
        .await?
        .ok_or(not_found)?;
    let mut realm_mappings = Vec::new();
    let mut client_mappings = Map::new();
    for (client, role) in &mappings {
        let fields = representation(role, &realm_id);
        match (client, &role.client) {
            (Some(client), Some(id)) => {
                let entry = client_mappings
                    .entry(client.clone())
                    .or_insert_with(|| json!({ "id": id, "client": client, "mappings": [] }));
                if let Some(Value::Array(roles)) = entry.get_mut("mappings") {
                    roles.push(fields);
                }
            }
            _ => realm_mappings.push(fields),
        }
    }
    let mut body = Map::new();
    if !realm_mappings.is_empty() {
        body.insert("realmMappings".into(), Value::Array(realm_mappings));
    }
    if !client_mappings.is_empty() {
        body.insert("clientMappings".into(), Value::Object(client_mappings));
    }
    Ok(json_response(Value::Object(body)))
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

/// Why a role list body was refused.
enum RoleListError {
    /// The body is not a JSON array.
    Malformed,
    /// An item lacks a string `id` or `name`.
    Incomplete,
    TooMany,
}

/// Parses a role list body into `(id, name)` pairs.
fn role_list(body: &[u8]) -> Result<Vec<(String, String)>, RoleListError> {
    let Ok(Value::Array(items)) = serde_json::from_slice::<Value>(body) else {
        return Err(RoleListError::Malformed);
    };
    if items.len() > 100 {
        return Err(RoleListError::TooMany);
    }
    items
        .iter()
        .map(|item| match (item.get("id"), item.get("name")) {
            (Some(Value::String(id)), Some(Value::String(name))) => Ok((id.clone(), name.clone())),
            _ => Err(RoleListError::Incomplete),
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
    let roles = role_list(&body).map_err(|error| match error {
        RoleListError::Malformed => unparsable(),
        RoleListError::Incomplete => {
            AdminError::Error(StatusCode::NOT_FOUND, "Role not found".into())
        }
        RoleListError::TooMany => AdminError::bad_request("Too many roles"),
    })?;
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
