//! Admin realm partial export and import.
//!
//! Follows `tests/reference/partial-export-observations.json` and
//! `tests/reference/partial-import-observations.json`. The realm
//! comes with its client scopes, required actions and default role;
//! `exportGroupsAndRoles` adds roles and the group tree with role
//! mappings, and `exportClients` adds the clients, secrets masked, with
//! their service-account users. Regular users are never exported.

use std::collections::HashMap;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use rs_keycloak_storage_postgres::{RoleHolder, RoleNames};
use serde_json::{Map, Value, json};

use super::users::{json_response, realm_id, representation as user_representation};
use super::{Access, AdminError, authorize};
use crate::oidc::OidcState;

/// How the reference shows a client secret in an export.
const MASKED_SECRET: &str = "**********";

pub(super) fn routes() -> Router<OidcState> {
    Router::new()
        .route("/admin/realms/{realm}/partial-export", post(partial_export))
        .route("/admin/realms/{realm}/partialImport", post(partial_import))
}

fn flag(params: &HashMap<String, String>, name: &str) -> Result<bool, AdminError> {
    match params.get(name).map(String::as_str) {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(AdminError::bad_request(format!("Invalid {name}"))),
    }
}

async fn partial_export(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    if let Some(name) = params
        .keys()
        .find(|name| !matches!(name.as_str(), "exportGroupsAndRoles" | "exportClients"))
    {
        return Err(AdminError::bad_request(format!(
            "Unsupported export parameter: {name}"
        )));
    }
    let groups_and_roles = flag(&params, "exportGroupsAndRoles")?;
    let clients = flag(&params, "exportClients")?;
    authorize(&state, &headers, &realm, Access::ViewRealm).await?;
    if groups_and_roles {
        authorize(&state, &headers, &realm, Access::ViewUsers).await?;
    }
    if clients {
        authorize(&state, &headers, &realm, Access::ViewClients).await?;
    }
    let record = state
        .storage
        .realm_by_name(&realm)
        .await?
        .ok_or(AdminError::RealmNotFound)?;
    let realm_id = realm_id(&state, &realm).await?;
    let mut export = super::realm_representation(&record);
    export["clientScopes"] = json!(super::client_scopes::all_scopes(&realm_id));
    let settings = state.storage.required_action_settings(&realm_id).await?;
    export["requiredActions"] = json!(super::authentication::all_actions(&settings));
    export["defaultRole"] = json!({
        "name": format!("default-roles-{}", record.name),
        "composite": true,
        "clientRole": false,
        "containerId": realm_id,
    });
    if groups_and_roles {
        export["roles"] = roles(&state, &realm_id, clients).await?;
        export["groups"] = json!(group_tree(&state, &realm_id, None).await?);
    }
    if clients {
        let mut listed = Vec::new();
        let mut users = Vec::new();
        for client in state.storage.clients(&realm_id, None).await? {
            let secret = (!client.public && !client.bearer_only).then(|| MASKED_SECRET.to_owned());
            if client.service_accounts
                && let Some(user_id) = state
                    .storage
                    .service_account_user_id(&realm_id, &client.id)
                    .await?
                && let Some(user) = state.storage.user(&realm_id, &user_id).await?
            {
                let mut user = user_representation(user);
                user["serviceAccountClientId"] = json!(client.client_identifier);
                users.push(user);
            }
            listed.push(super::clients::representation(&client, secret));
        }
        export["clients"] = json!(listed);
        export["users"] = json!(users);
    }
    Ok(json_response(export).into_response())
}

/// Realm roles, and with `with_clients` client roles by public client
/// identifier; the reference exports client roles only with the clients.
async fn roles(state: &OidcState, realm_id: &str, with_clients: bool) -> Result<Value, AdminError> {
    let realm_roles = state.storage.roles(realm_id, None).await?;
    let mut client_roles = Map::new();
    let clients = if with_clients {
        state.storage.clients(realm_id, None).await?
    } else {
        Vec::new()
    };
    for client in clients {
        let roles = state.storage.roles(realm_id, Some(&client.id)).await?;
        if !roles.is_empty() {
            client_roles.insert(
                client.client_identifier,
                json!(
                    roles
                        .iter()
                        .map(|role| super::roles::representation(role, realm_id))
                        .collect::<Vec<_>>()
                ),
            );
        }
    }
    Ok(json!({
        "realm": realm_roles.iter().map(|role| super::roles::representation(role, realm_id)).collect::<Vec<_>>(),
        "client": client_roles,
    }))
}

/// The groups under `parent`, each with its role mappings and subgroups.
async fn group_tree(
    state: &OidcState,
    realm_id: &str,
    parent: Option<&str>,
) -> Result<Vec<Value>, AdminError> {
    let mut tree = Vec::new();
    for group in state.storage.groups(realm_id, parent).await? {
        let roles: RoleNames = state
            .storage
            .holder_role_names(realm_id, RoleHolder::Group(&group.id))
            .await?;
        let mut fields = super::groups::full(&group, &roles);
        fields["subGroups"] = json!(Box::pin(group_tree(state, realm_id, Some(&group.id))).await?);
        tree.push(fields);
    }
    Ok(tree)
}

/// What an import does with a resource that already exists.
#[derive(Clone, Copy, PartialEq, Eq)]
enum IfExists {
    Fail,
    Skip,
    Overwrite,
}

/// One imported resource, as the import's answer lists it.
fn result(action: &str, resource_type: &str, name: &str, id: &str) -> Value {
    json!({ "action": action, "resourceType": resource_type, "resourceName": name, "id": id })
}

fn items<'a>(
    body: &'a Map<String, Value>,
    name: &str,
) -> Result<Vec<&'a Map<String, Value>>, AdminError> {
    match body.get(name) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_object().ok_or_else(super::users::unparsable))
            .collect(),
        Some(_) => Err(super::users::unparsable()),
    }
}

fn text<'a>(
    item: &'a Map<String, Value>,
    name: &str,
    missing: &str,
) -> Result<&'a str, AdminError> {
    item.get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AdminError::bad_request(missing.to_owned()))
}

/// Imports realm roles, clients and users. Under `FAIL` every resource is
/// checked before anything is written, so a conflict changes nothing.
/// Groups are refused: the reference fails on them without a path.
async fn partial_import(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageRealm).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let body = super::users::json_object(&body)?;
    if let Some(field) = body.keys().find(|key| {
        !matches!(
            key.as_str(),
            "ifResourceExists" | "roles" | "clients" | "users" | "policy"
        )
    }) {
        return Err(AdminError::bad_request(format!(
            "Unsupported import section: {field}"
        )));
    }
    let policy = match body.get("ifResourceExists").or_else(|| body.get("policy")) {
        None | Some(Value::Null) => IfExists::Fail,
        Some(Value::String(policy)) if policy == "FAIL" => IfExists::Fail,
        Some(Value::String(policy)) if policy == "SKIP" => IfExists::Skip,
        Some(Value::String(policy)) if policy == "OVERWRITE" => IfExists::Overwrite,
        Some(_) => return Err(AdminError::bad_request("Invalid ifResourceExists")),
    };
    let roles = match body.get("roles") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(roles)) => {
            if let Some(field) = roles.keys().find(|key| key.as_str() != "realm") {
                return Err(AdminError::bad_request(format!(
                    "Unsupported import section: roles.{field}"
                )));
            }
            items(roles, "realm")?
        }
        Some(_) => return Err(super::users::unparsable()),
    };
    let clients = items(&body, "clients")?;
    let users = items(&body, "users")?;
    let needs = [
        (!clients.is_empty(), Access::ManageClients),
        (!users.is_empty(), Access::ManageUsers),
    ];
    for (needed, access) in needs {
        if needed {
            authorize(&state, &headers, &realm, access).await?;
        }
    }
    // What already exists, by name, with its id.
    let mut existing_clients = Vec::new();
    for client in &clients {
        let name = text(client, "clientId", "Client id is missing")?;
        existing_clients.push(
            state
                .storage
                .clients(&realm_id, Some(name))
                .await?
                .into_iter()
                .next(),
        );
    }
    let mut existing_roles = Vec::new();
    for role in &roles {
        let (name, _) = super::roles::name_and_description(role)?;
        existing_roles.push(state.storage.role(&realm_id, None, name).await?);
    }
    let mut existing_users = Vec::new();
    for user in &users {
        let name = text(user, "username", "User name is missing")?.to_lowercase();
        let found = state
            .storage
            .search_users(
                &realm_id,
                &rs_keycloak_storage_postgres::UserQuery {
                    username: Some(&super::users::like_literal(&name)),
                    ..Default::default()
                },
                0,
                1,
            )
            .await?
            .into_iter()
            .next();
        existing_users.push(found);
    }
    if policy == IfExists::Fail {
        let conflict = clients
            .iter()
            .zip(&existing_clients)
            .find(|(_, found)| found.is_some())
            .map(|(client, _)| {
                format!(
                    "Client id '{}' already exists",
                    client["clientId"].as_str().unwrap_or_default()
                )
            })
            .or_else(|| {
                roles
                    .iter()
                    .zip(&existing_roles)
                    .find(|(_, found)| found.is_some())
                    .map(|(role, _)| {
                        format!(
                            "Realm role '{}' already exists",
                            role["name"].as_str().unwrap_or_default()
                        )
                    })
            })
            .or_else(|| {
                users
                    .iter()
                    .zip(&existing_users)
                    .find(|(_, found)| found.is_some())
                    .map(|(user, _)| {
                        format!(
                            "User '{}' already exists",
                            user["username"].as_str().unwrap_or_default()
                        )
                    })
            });
        if let Some(message) = conflict {
            return Err(AdminError::Message(
                axum::http::StatusCode::CONFLICT,
                message,
            ));
        }
    }
    let mut results = Vec::new();
    let (mut added, mut skipped, mut overwritten) = (0, 0, 0);
    for (client, found) in clients.into_iter().zip(existing_clients) {
        let name = client["clientId"].as_str().unwrap_or_default().to_owned();
        match (found, policy) {
            (None, _) => {
                let id = super::clients::create_from(&state, &realm_id, client, &actor).await?;
                added += 1;
                results.push(result("ADDED", "CLIENT", &name, &id));
            }
            (Some(stored), IfExists::Overwrite) => {
                let id = stored.id.clone();
                super::clients::update_from(&state, &realm_id, stored, client, &actor).await?;
                overwritten += 1;
                results.push(result("OVERWRITTEN", "CLIENT", &name, &id));
            }
            (Some(stored), _) => {
                skipped += 1;
                results.push(result("SKIPPED", "CLIENT", &name, &stored.id));
            }
        }
    }
    for (role, found) in roles.into_iter().zip(existing_roles) {
        let (name, description) = super::roles::name_and_description(role)?;
        match (found, policy) {
            (None, _) => {
                let id = uuid::Uuid::new_v4().to_string();
                let composites = RoleNames::default();
                let new_role = rs_keycloak_storage_postgres::NewRole {
                    id: &id,
                    name,
                    description,
                    composites: &composites,
                };
                state
                    .storage
                    .create_role(&realm_id, None, &new_role, &actor)
                    .await?;
                added += 1;
                results.push(result("ADDED", "REALM_ROLE", name, &id));
            }
            (Some(stored), IfExists::Overwrite) => {
                state
                    .storage
                    .update_role(&realm_id, None, name, name, description, &actor)
                    .await?;
                overwritten += 1;
                results.push(result("OVERWRITTEN", "REALM_ROLE", name, &stored.id));
            }
            (Some(stored), _) => {
                skipped += 1;
                results.push(result("SKIPPED", "REALM_ROLE", name, &stored.id));
            }
        }
    }
    for (user, found) in users.into_iter().zip(existing_users) {
        let name = user["username"].as_str().unwrap_or_default().to_lowercase();
        match (found, policy) {
            (None, _) => {
                let id = super::users::create_from(&state, &realm_id, user, &actor).await?;
                added += 1;
                results.push(result("ADDED", "USER", &name, &id));
            }
            (Some(stored), IfExists::Overwrite) => {
                super::users::update_from(&state, &realm_id, &stored, user, &actor).await?;
                overwritten += 1;
                results.push(result("OVERWRITTEN", "USER", &name, &stored.id));
            }
            (Some(stored), _) => {
                skipped += 1;
                results.push(result("SKIPPED", "USER", &name, &stored.id));
            }
        }
    }
    Ok(json_response(json!({
        "overwritten": overwritten,
        "added": added,
        "skipped": skipped,
        "results": results,
    })))
}
