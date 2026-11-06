//! Admin REST routes for listing and ending user sessions.
//!
//! Follows `tests/reference/admin-session-observations.json`. Client
//! addresses are not recorded, so session representations have no
//! `ipAddress`.

use std::collections::HashMap;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{delete, get, post};
use rs_keycloak_storage_postgres::SessionRecord;
use serde_json::{Map, Value, json};

use super::users::{json_response, realm_id};
use super::{Access, AdminError, authorize};
use crate::oidc::OidcState;

pub(super) fn routes() -> Router<OidcState> {
    Router::new()
        .route(
            "/admin/realms/{realm}/users/{user}/sessions",
            get(user_sessions),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/logout",
            post(logout_user),
        )
        .route(
            "/admin/realms/{realm}/sessions/{session}",
            delete(end_session),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/user-sessions",
            get(client_sessions),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/session-count",
            get(session_count),
        )
        .route(
            "/admin/realms/{realm}/client-session-stats",
            get(session_stats),
        )
        .route("/admin/realms/{realm}/logout-all", post(logout_all))
        .route(
            "/admin/realms/{realm}/users/{user}/offline-sessions/{client}",
            get(user_offline_sessions),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/offline-sessions",
            get(client_offline_sessions),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/offline-session-count",
            get(offline_session_count),
        )
}

fn representation(session: &SessionRecord) -> Value {
    let clients: Map<String, Value> = session
        .clients
        .iter()
        .map(|(id, client)| (id.clone(), json!(client)))
        .collect();
    json!({
        "id": session.id,
        "username": session.username,
        "userId": session.user_id,
        "start": session.started,
        "lastAccess": session.last_access,
        "rememberMe": false,
        "clients": clients,
        "transientUser": false,
    })
}

fn sessions_response(sessions: &[SessionRecord]) -> Response {
    json_response(Value::Array(sessions.iter().map(representation).collect()))
}

fn user_not_found() -> AdminError {
    AdminError::Error(StatusCode::NOT_FOUND, "User not found".into())
}

async fn client_id(state: &OidcState, realm_id: &str, client: &str) -> Result<String, AdminError> {
    Ok(state
        .storage
        .client(realm_id, client)
        .await?
        .ok_or_else(|| AdminError::Error(StatusCode::NOT_FOUND, "Could not find client".into()))?
        .id)
}

async fn user_sessions(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let sessions = state
        .storage
        .user_session_list(&realm_id, &user)
        .await?
        .ok_or_else(user_not_found)?;
    Ok(sessions_response(&sessions))
}

async fn logout_user(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    if state
        .storage
        .admin_end_sessions(&realm_id, Some(&user), &actor)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(user_not_found())
    }
}

async fn end_session(
    State(state): State<OidcState>,
    Path((realm, session)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    if state
        .storage
        .admin_end_session(&realm_id, &session, &actor)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        // The reference spells it this way.
        Err(AdminError::Error(
            StatusCode::NOT_FOUND,
            "Sesssion not found".into(),
        ))
    }
}

async fn client_sessions(
    State(state): State<OidcState>,
    Path((realm, client)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewClients).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let client = client_id(&state, &realm_id, &client).await?;
    let number = |name: &str, default: i64| match params.get(name) {
        None => Ok(default),
        Some(value) => value
            .parse::<i64>()
            .ok()
            .filter(|value| *value >= 0)
            .ok_or_else(|| AdminError::bad_request(format!("Invalid {name}"))),
    };
    let first = number("first", 0)?;
    let max = number("max", 100)?.min(1000);
    let sessions = state
        .storage
        .client_session_list(&realm_id, &client, first, max)
        .await?;
    Ok(sessions_response(&sessions))
}

async fn session_count(
    State(state): State<OidcState>,
    Path((realm, client)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewClients).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let client = client_id(&state, &realm_id, &client).await?;
    let count = state
        .storage
        .client_session_counts(&realm_id)
        .await?
        .into_iter()
        .find(|entry| entry.id == client)
        .map_or(0, |entry| entry.active);
    Ok(json_response(json!({ "count": count })))
}

/// Active and offline counts per client with sessions; the reference sends
/// them as strings.
async fn session_stats(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewRealm).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let counts = state.storage.client_session_counts(&realm_id).await?;
    Ok(json_response(Value::Array(
        counts
            .iter()
            .map(|entry| {
                json!({
                    "id": entry.id,
                    "clientId": entry.client_identifier,
                    "active": entry.active.to_string(),
                    "offline": entry.offline.to_string(),
                })
            })
            .collect(),
    )))
}

async fn user_offline_sessions(
    State(state): State<OidcState>,
    Path((realm, user, client)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    state
        .storage
        .user(&realm_id, &user)
        .await?
        .ok_or_else(user_not_found)?;
    let client = client_id(&state, &realm_id, &client).await?;
    let sessions = state
        .storage
        .offline_session_list(&realm_id, &client, Some(&user))
        .await?;
    Ok(sessions_response(&sessions))
}

async fn client_offline_sessions(
    State(state): State<OidcState>,
    Path((realm, client)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewClients).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let client = client_id(&state, &realm_id, &client).await?;
    let sessions = state
        .storage
        .offline_session_list(&realm_id, &client, None)
        .await?;
    Ok(sessions_response(&sessions))
}

async fn offline_session_count(
    State(state): State<OidcState>,
    Path((realm, client)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewClients).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let client = client_id(&state, &realm_id, &client).await?;
    let count = state
        .storage
        .client_session_counts(&realm_id)
        .await?
        .into_iter()
        .find(|entry| entry.id == client)
        .map_or(0, |entry| entry.offline);
    Ok(json_response(json!({ "count": count })))
}

async fn logout_all(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageRealm).await?;
    let realm_id = realm_id(&state, &realm).await?;
    state
        .storage
        .admin_end_sessions(&realm_id, None, &actor)
        .await?;
    Ok(json_response(json!({})))
}
