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
    // `ExportUtils.exportRealm` always sets the realm's texts.
    export["localizationTexts"] = json!(state.storage.localization_texts(&realm_id).await?);
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

/// Imports realm and client roles, clients, groups and users, in that
/// order so that later resources can name earlier ones. Under `FAIL` every
/// resource is checked before anything is written, so a conflict changes
/// nothing. Groups need no path, which the reference requires.
async fn partial_import(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageRealm).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let mut body = super::users::json_object(&body)?;
    strip_export_fields(&mut body);
    if let Some(field) = body.keys().find(|key| {
        !matches!(
            key.as_str(),
            "ifResourceExists" | "roles" | "clients" | "groups" | "users" | "policy"
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
    let (roles, client_roles) = match body.get("roles") {
        None | Some(Value::Null) => (Vec::new(), Vec::new()),
        Some(Value::Object(roles)) => {
            if let Some(field) = roles
                .keys()
                .find(|key| !matches!(key.as_str(), "realm" | "client"))
            {
                return Err(AdminError::bad_request(format!(
                    "Unsupported import section: roles.{field}"
                )));
            }
            let mut by_client = Vec::new();
            match roles.get("client") {
                None | Some(Value::Null) => (),
                Some(Value::Object(clients)) => {
                    for (client, _) in clients {
                        by_client.push((client.clone(), items(clients, client)?));
                    }
                }
                Some(_) => return Err(super::users::unparsable()),
            }
            (items(roles, "realm")?, by_client)
        }
        Some(_) => return Err(super::users::unparsable()),
    };
    let clients = items(&body, "clients")?;
    let groups = items(&body, "groups")?;
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
    let top_level = state.storage.groups(&realm_id, None).await?;
    let mut existing_groups = Vec::new();
    for group in &groups {
        let name = text(group, "name", "Group name is missing")?;
        existing_groups.push(
            top_level
                .iter()
                .find(|stored| stored.name == name)
                .map(|stored| stored.id.clone()),
        );
    }
    let mut existing_client_roles = Vec::new();
    for (client, roles) in &client_roles {
        let stored = state
            .storage
            .clients(&realm_id, Some(client))
            .await?
            .into_iter()
            .next();
        for role in roles {
            let (name, _) = super::roles::name_and_description(role)?;
            let found = match &stored {
                Some(stored) => {
                    state
                        .storage
                        .role(&realm_id, Some(&stored.id), name)
                        .await?
                }
                None => None,
            };
            existing_client_roles.push(found);
        }
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
    let mut existing_client_roles = existing_client_roles.into_iter();
    for (client, roles) in &client_roles {
        let stored = state
            .storage
            .clients(&realm_id, Some(client))
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| AdminError::bad_request(format!("Client {client} not found")))?;
        for role in roles {
            let (name, description) = super::roles::name_and_description(role)?;
            let label = format!("{client}-->{name}");
            match (existing_client_roles.next().flatten(), policy) {
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
                        .create_role(&realm_id, Some(&stored.id), &new_role, &actor)
                        .await?;
                    added += 1;
                    results.push(result("ADDED", "CLIENT_ROLE", &label, &id));
                }
                (Some(found), IfExists::Overwrite) => {
                    state
                        .storage
                        .update_role(&realm_id, Some(&stored.id), name, name, description, &actor)
                        .await?;
                    overwritten += 1;
                    results.push(result("OVERWRITTEN", "CLIENT_ROLE", &label, &found.id));
                }
                (Some(found), _) => {
                    skipped += 1;
                    results.push(result("SKIPPED", "CLIENT_ROLE", &label, &found.id));
                }
            }
        }
    }
    for (group, found) in groups.into_iter().zip(existing_groups) {
        let name = group["name"].as_str().unwrap_or_default().to_owned();
        match (found, policy) {
            (Some(id), IfExists::Skip) => {
                skipped += 1;
                results.push(result("SKIPPED", "GROUP", &name, &id));
            }
            (found, _) => {
                let overwriting = found.is_some();
                let id = import_group(&state, &realm_id, None, group, &actor).await?;
                if overwriting {
                    overwritten += 1;
                    results.push(result("OVERWRITTEN", "GROUP", &name, &id));
                } else {
                    added += 1;
                    results.push(result("ADDED", "GROUP", &name, &id));
                }
            }
        }
    }
    for (user, found) in users.into_iter().zip(existing_users) {
        let name = user["username"].as_str().unwrap_or_default().to_lowercase();
        match (found, policy) {
            (None, _) => {
                let mut created = user.clone();
                for field in ["realmRoles", "clientRoles", "groups"] {
                    created.remove(field);
                }
                let id = super::users::create_from(&state, &realm_id, &created, &actor).await?;
                user_links(&state, &realm_id, &id, user, &actor).await?;
                added += 1;
                results.push(result("ADDED", "USER", &name, &id));
            }
            (Some(stored), IfExists::Overwrite) => {
                let mut changed = user.clone();
                for field in ["realmRoles", "clientRoles", "groups"] {
                    changed.remove(field);
                }
                super::users::update_from(&state, &realm_id, &stored, &changed, &actor).await?;
                user_links(&state, &realm_id, &stored.id, user, &actor).await?;
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

/// Maps an imported holder's `realmRoles` and `clientRoles` (role names by
/// public client identifier) to it.
async fn map_roles(
    state: &OidcState,
    realm_id: &str,
    holder: RoleHolder<'_>,
    item: &Map<String, Value>,
    actor: &rs_keycloak_storage_postgres::Actor,
) -> Result<(), AdminError> {
    let names = |value: Option<&Value>| -> Result<Vec<String>, AdminError> {
        match value {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(names)) => names
                .iter()
                .map(|name| {
                    name.as_str()
                        .map(str::to_owned)
                        .ok_or_else(super::users::unparsable)
                })
                .collect(),
            Some(_) => Err(super::users::unparsable()),
        }
    };
    let mut containers = vec![(None, names(item.get("realmRoles"))?)];
    match item.get("clientRoles") {
        None | Some(Value::Null) => (),
        Some(Value::Object(clients)) => {
            for (client, roles) in clients {
                let stored = state
                    .storage
                    .clients(realm_id, Some(client))
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| AdminError::bad_request(format!("Client {client} not found")))?;
                containers.push((Some(stored.id), names(Some(roles))?));
            }
        }
        Some(_) => return Err(super::users::unparsable()),
    }
    for (client, names) in containers {
        let mut refs = Vec::new();
        for name in names {
            let role = state
                .storage
                .role(realm_id, client.as_deref(), &name)
                .await?
                .ok_or_else(|| AdminError::bad_request(format!("Role not found: {name}")))?;
            refs.push((role.id, name));
        }
        if !refs.is_empty() {
            state
                .storage
                .change_holder_roles(realm_id, client.as_deref(), holder, &refs, true, actor)
                .await?;
        }
    }
    Ok(())
}

/// Creates a group under `parent` unless it exists there, then maps its
/// roles and imports its subgroups; returns its id.
async fn import_group(
    state: &OidcState,
    realm_id: &str,
    parent: Option<&str>,
    group: &Map<String, Value>,
    actor: &rs_keycloak_storage_postgres::Actor,
) -> Result<String, AdminError> {
    let name = text(group, "name", "Group name is missing")?;
    let siblings = state.storage.groups(realm_id, parent).await?;
    let id = match siblings.into_iter().find(|sibling| sibling.name == name) {
        Some(existing) => existing.id,
        None => {
            let id = uuid::Uuid::new_v4().to_string();
            match state
                .storage
                .create_group(realm_id, &id, parent, name, actor)
                .await?
            {
                rs_keycloak_storage_postgres::GroupCreation::Created(_) => id,
                _ => {
                    return Err(AdminError::bad_request(format!(
                        "Could not import group {name}"
                    )));
                }
            }
        }
    };
    map_roles(state, realm_id, RoleHolder::Group(&id), group, actor).await?;
    for child in items(group, "subGroups")? {
        Box::pin(import_group(state, realm_id, Some(&id), child, actor)).await?;
    }
    Ok(id)
}

/// Maps an imported user's roles and joins the groups named by path.
async fn user_links(
    state: &OidcState,
    realm_id: &str,
    user_id: &str,
    user: &Map<String, Value>,
    actor: &rs_keycloak_storage_postgres::Actor,
) -> Result<(), AdminError> {
    map_roles(state, realm_id, RoleHolder::User(user_id), user, actor).await?;
    let paths = match user.get("groups") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(paths)) => paths
            .iter()
            .map(|path| path.as_str().ok_or_else(super::users::unparsable))
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(super::users::unparsable()),
    };
    for path in paths {
        let mut parent: Option<String> = None;
        for name in path.split('/').filter(|name| !name.is_empty()) {
            let found = state
                .storage
                .groups(realm_id, parent.as_deref())
                .await?
                .into_iter()
                .find(|group| group.name == name)
                .ok_or_else(|| AdminError::bad_request(format!("Group not found: {path}")))?;
            parent = Some(found.id);
        }
        let group =
            parent.ok_or_else(|| AdminError::bad_request(format!("Group not found: {path}")))?;
        state
            .storage
            .change_membership(realm_id, user_id, &group, true, actor)
            .await?;
    }
    Ok(())
}

/// Realm fields an export carries that import leaves alone, as the
/// reference's partial import does.
const REALM_FIELDS: [&str; 19] = [
    "loginWithEmailAllowed",
    "duplicateEmailsAllowed",
    "id",
    "localizationTexts",
    "realm",
    "enabled",
    "displayName",
    "accessTokenLifespan",
    "internationalizationEnabled",
    "supportedLocales",
    "defaultLocale",
    "editUsernameAllowed",
    "registrationEmailAsUsername",
    "resetPasswordAllowed",
    "verifyEmail",
    "smtpServer",
    "clientScopes",
    "requiredActions",
    "defaultRole",
];

/// Removes what a partial export adds but an import cannot take, so an
/// export imports as is: realm settings, identifiers, read-only fields,
/// masked secrets (a new one is generated) and service-account users
/// (created with their clients).
fn strip_export_fields(body: &mut Map<String, Value>) {
    for field in REALM_FIELDS {
        body.remove(field);
    }
    body.retain(|field, _| !super::login_settings::represented(field));
    let remove = |item: &mut Value, fields: &[&str]| {
        if let Some(item) = item.as_object_mut() {
            for field in fields {
                item.remove(*field);
            }
            if item.get("attributes") == Some(&json!({})) {
                item.remove("attributes");
            }
        }
    };
    if let Some(Value::Array(clients)) = body.get_mut("clients") {
        for client in clients {
            remove(
                client,
                &["id", "defaultClientScopes", "optionalClientScopes"],
            );
            if client.get("secret").and_then(Value::as_str) == Some(MASKED_SECRET)
                && let Some(client) = client.as_object_mut()
            {
                client.remove("secret");
            }
        }
    }
    if let Some(Value::Array(users)) = body.get_mut("users") {
        users.retain(|user| user.get("serviceAccountClientId").is_none());
        for user in users {
            remove(
                user,
                &[
                    "id",
                    "createdTimestamp",
                    "totp",
                    "disableableCredentialTypes",
                    "notBefore",
                ],
            );
        }
    }
    if let Some(Value::Object(roles)) = body.get_mut("roles") {
        let realm_roles = roles
            .get_mut("realm")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten();
        for role in realm_roles {
            remove(role, &["id", "composite", "clientRole", "containerId"]);
        }
        if let Some(Value::Object(clients)) = roles.get_mut("client") {
            for role in clients
                .values_mut()
                .filter_map(Value::as_array_mut)
                .flatten()
            {
                remove(role, &["id", "composite", "clientRole", "containerId"]);
            }
        }
    }
    fn strip_group(group: &mut Value) {
        if let Some(fields) = group.as_object_mut() {
            for field in ["id", "path", "parentId", "subGroupCount", "access"] {
                fields.remove(field);
            }
            if fields.get("attributes") == Some(&json!({})) {
                fields.remove("attributes");
            }
            if let Some(Value::Array(children)) = fields.get_mut("subGroups") {
                children.iter_mut().for_each(strip_group);
            }
        }
    }
    if let Some(Value::Array(groups)) = body.get_mut("groups") {
        groups.iter_mut().for_each(strip_group);
    }
}
