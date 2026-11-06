//! Admin realm partial export.
//!
//! Follows `tests/reference/partial-export-observations.json`. The realm
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
    Router::new().route("/admin/realms/{realm}/partial-export", post(partial_export))
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
