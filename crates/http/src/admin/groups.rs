//! Admin REST routes for groups, subgroups and user membership.
//!
//! Follows the recorded cases in `tests/reference/admin-group-observations.json`.
//! Group attributes and group role mappings are not modelled and are refused.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use rs_keycloak_storage_postgres::{GroupCreation, GroupRecord, MembershipChange};
use serde_json::{Value, json};
use uuid::Uuid;

use super::users::{
    json_object, json_response, realm_id, representation as user_representation, unparsable,
};
use super::{AdminError, authorize};
use crate::oidc::OidcState;

pub(super) fn routes() -> Router<OidcState> {
    Router::new()
        .route(
            "/admin/realms/{realm}/groups",
            get(list_groups).post(create_top_level),
        )
        .route("/admin/realms/{realm}/groups/count", get(count_groups))
        .route(
            "/admin/realms/{realm}/groups/{group}",
            get(read_group).delete(delete_group),
        )
        .route(
            "/admin/realms/{realm}/groups/{group}/children",
            get(list_children).post(create_child),
        )
        .route("/admin/realms/{realm}/groups/{group}/members", get(members))
        .route(
            "/admin/realms/{realm}/users/{user}/groups",
            get(user_groups),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/groups/{group}",
            put(join_group).delete(leave_group),
        )
}

fn group_not_found() -> AdminError {
    AdminError::Error(StatusCode::NOT_FOUND, "Could not find group by id".into())
}

/// The brief form used in lists.
fn brief(group: &GroupRecord) -> Value {
    let mut fields = json!({
        "id": group.id,
        "name": group.name,
        "path": group.path,
        "subGroupCount": group.sub_group_count,
        "subGroups": [],
    });
    if let Some(parent_id) = &group.parent_id {
        fields["parentId"] = json!(parent_id);
    }
    fields
}

/// The full form returned for a single group.
fn full(group: &GroupRecord) -> Value {
    let mut fields = brief(group);
    fields["attributes"] = json!({});
    fields["realmRoles"] = json!([]);
    fields["clientRoles"] = json!({});
    fields
}

/// Reads the group name from a creation body.
fn group_name(body: &[u8]) -> Result<String, AdminError> {
    let fields = json_object(body)?;
    if let Some(field) = fields.keys().find(|key| key.as_str() != "name") {
        return Err(AdminError::bad_request(format!(
            "Unsupported group field: {field}"
        )));
    }
    let name = match fields.get("name") {
        None | Some(Value::Null) => "",
        Some(Value::String(name)) => name.trim(),
        Some(_) => return Err(unparsable()),
    };
    if name.is_empty() {
        return Err(AdminError::bad_request("Group name is missing"));
    }
    if name.len() > 255 || name.contains('/') || name.contains(char::is_control) {
        return Err(AdminError::bad_request("Invalid group name"));
    }
    Ok(name.to_owned())
}

async fn create(
    state: &OidcState,
    realm: &str,
    headers: &HeaderMap,
    parent_id: Option<&str>,
    body: &[u8],
) -> Result<Response, AdminError> {
    let actor = authorize(state, headers).await?;
    let realm_id = realm_id(state, realm).await?;
    let name = group_name(body)?;
    let id = Uuid::new_v4().to_string();
    match state
        .storage
        .create_group(&realm_id, &id, parent_id, &name, &actor)
        .await?
    {
        GroupCreation::Created(group) => {
            let location = format!(
                "{}/admin/realms/{realm}/groups/{id}",
                state.issuer_base.trim_end_matches('/')
            );
            let location = HeaderValue::from_str(&location).map_err(|_| AdminError::Unavailable)?;
            // The reference returns the new group only for subgroups.
            if parent_id.is_some() {
                let mut fields = full(&group);
                if let Some(object) = fields.as_object_mut() {
                    object.remove("subGroupCount");
                }
                Ok((
                    StatusCode::CREATED,
                    [(header::LOCATION, location)],
                    json_response(fields),
                )
                    .into_response())
            } else {
                Ok((StatusCode::CREATED, [(header::LOCATION, location)]).into_response())
            }
        }
        GroupCreation::Exists if parent_id.is_some() => Err(AdminError::Message(
            StatusCode::CONFLICT,
            format!("Sibling group named '{name}' already exists."),
        )),
        GroupCreation::Exists => Err(AdminError::Message(
            StatusCode::CONFLICT,
            format!("Top level group named '{name}' already exists."),
        )),
        GroupCreation::ParentNotFound => Err(group_not_found()),
    }
}

async fn create_top_level(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AdminError> {
    create(&state, &realm, &headers, None, &body).await
}

async fn create_child(
    State(state): State<OidcState>,
    Path((realm, parent)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AdminError> {
    create(&state, &realm, &headers, Some(&parent), &body).await
}

async fn list(
    state: &OidcState,
    realm: &str,
    headers: &HeaderMap,
    parent: Option<&str>,
) -> Result<Response, AdminError> {
    authorize(state, headers).await?;
    let realm_id = realm_id(state, realm).await?;
    if let Some(parent) = parent {
        state
            .storage
            .group(&realm_id, parent)
            .await?
            .ok_or_else(group_not_found)?;
    }
    let groups = state.storage.groups(&realm_id, parent).await?;
    let render = if parent.is_some() { full } else { brief };
    Ok(json_response(Value::Array(
        groups.iter().map(render).collect(),
    )))
}

async fn list_groups(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    list(&state, &realm, &headers, None).await
}

async fn list_children(
    State(state): State<OidcState>,
    Path((realm, parent)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    list(&state, &realm, &headers, Some(&parent)).await
}

async fn count_groups(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    Ok(json_response(
        json!({ "count": state.storage.count_groups(&realm_id).await? }),
    ))
}

async fn read_group(
    State(state): State<OidcState>,
    Path((realm, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let group = state
        .storage
        .group(&realm_id, &id)
        .await?
        .ok_or_else(group_not_found)?;
    Ok(json_response(full(&group)))
}

async fn delete_group(
    State(state): State<OidcState>,
    Path((realm, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    if state.storage.delete_group(&realm_id, &id, &actor).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(group_not_found())
    }
}

async fn members(
    State(state): State<OidcState>,
    Path((realm, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    state
        .storage
        .group(&realm_id, &id)
        .await?
        .ok_or_else(group_not_found)?;
    let users = state.storage.group_members(&realm_id, &id).await?;
    Ok(json_response(Value::Array(
        users.into_iter().map(user_representation).collect(),
    )))
}

async fn user_groups(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let groups = state
        .storage
        .user_groups(&realm_id, &user)
        .await?
        .ok_or_else(|| AdminError::Error(StatusCode::NOT_FOUND, "User not found".into()))?;
    let listed = groups
        .iter()
        .map(|group| {
            let mut fields = brief(group);
            if let Some(object) = fields.as_object_mut() {
                object.remove("subGroupCount");
            }
            fields
        })
        .collect();
    Ok(json_response(Value::Array(listed)))
}

async fn change(
    state: OidcState,
    realm: String,
    user: String,
    group: String,
    headers: HeaderMap,
    join: bool,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    match state
        .storage
        .change_membership(&realm_id, &user, &group, join, &actor)
        .await?
    {
        MembershipChange::Changed => Ok(StatusCode::NO_CONTENT),
        MembershipChange::UserNotFound => Err(AdminError::Error(
            StatusCode::NOT_FOUND,
            "User not found".into(),
        )),
        MembershipChange::GroupNotFound => Err(AdminError::Error(
            StatusCode::NOT_FOUND,
            "Group not found".into(),
        )),
    }
}

async fn join_group(
    State(state): State<OidcState>,
    Path((realm, user, group)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    change(state, realm, user, group, headers, true).await
}

async fn leave_group(
    State(state): State<OidcState>,
    Path((realm, user, group)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    change(state, realm, user, group, headers, false).await
}
