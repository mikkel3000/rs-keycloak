//! Admin REST routes for brute-force detection, as the reference's
//! `AttackDetectionResource`: a user's failure state, which answers the
//! defaults for unprotected realms and unknown users, and clearing one
//! user's or every user's failures.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{delete, get};
use serde_json::json;

use super::users::{json_response, realm_id};
use super::{Access, AdminError, authorize};
use crate::oidc::OidcState;

pub(super) fn routes() -> Router<OidcState> {
    Router::new()
        .route(
            "/admin/realms/{realm}/attack-detection/brute-force/users",
            delete(clear_all),
        )
        .route(
            "/admin/realms/{realm}/attack-detection/brute-force/users/{user}",
            get(status).delete(clear_user),
        )
}

async fn status(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let found = state.storage.brute_force_status(&realm_id, &user).await?;
    Ok(json_response(json!({
        "disabled": found.disabled,
        "numFailures": found.num_failures,
        "numSecondaryAuthFailures": 0,
        "numTemporaryLockouts": found.num_temporary_lockouts,
        "lastFailure": found.last_failure,
        "lastIPFailure": found.last_ip_failure,
        "failedLoginNotBefore": found.failed_login_not_before,
    })))
}

async fn clear_user(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    state
        .storage
        .clear_brute_force(&realm_id, Some(&user), &actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn clear_all(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    state
        .storage
        .clear_brute_force(&realm_id, None, &actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
