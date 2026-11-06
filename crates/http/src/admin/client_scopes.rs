//! Read-only admin routes for the client scopes this server performs.
//!
//! Follows `tests/reference/client-scope-observations.json`. Client scopes
//! are not stored: every client has the same default scopes, `basic`
//! (`sub`), `email`, `profile` and `roles` (the role claims), and no
//! optional ones, so only those four are listed. Their identifiers are
//! derived from the realm and the name, so they are stable without storage.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::get;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::{Builder, Uuid};

use super::users::{json_response, realm_id};
use super::{Access, AdminError, authorize};
use crate::oidc::OidcState;

/// Name, description and the reference's `include.in.token.scope` and
/// `display.on.consent.screen` attributes, in name order.
const SCOPES: [(&str, &str, &str, &str); 4] = [
    (
        "basic",
        "OpenID Connect scope for add all basic claims to the token",
        "false",
        "false",
    ),
    (
        "email",
        "OpenID Connect built-in scope: email",
        "true",
        "true",
    ),
    (
        "profile",
        "OpenID Connect built-in scope: profile",
        "true",
        "true",
    ),
    (
        "roles",
        "OpenID Connect scope for add user roles to the access token",
        "false",
        "true",
    ),
];

pub(super) fn routes() -> Router<OidcState> {
    Router::new()
        .route("/admin/realms/{realm}/client-scopes", get(list_scopes))
        .route("/admin/realms/{realm}/client-scopes/{id}", get(read_scope))
        .route(
            "/admin/realms/{realm}/default-default-client-scopes",
            get(realm_defaults),
        )
        .route(
            "/admin/realms/{realm}/default-optional-client-scopes",
            get(no_scopes),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/default-client-scopes",
            get(client_defaults),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/optional-client-scopes",
            get(client_optional),
        )
}

/// A stable identifier for a realm's scope: a version 8 UUID of a hash.
fn scope_id(realm_id: &str, name: &str) -> Uuid {
    let digest =
        Sha256::digest([realm_id.as_bytes(), b"\0client-scope\0", name.as_bytes()].concat());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    Builder::from_custom_bytes(bytes).into_uuid()
}

fn representation(
    realm_id: &str,
    (name, description, in_token, on_consent): (&str, &str, &str, &str),
) -> Value {
    json!({
        "id": scope_id(realm_id, name).to_string(),
        "name": name,
        "description": description,
        "protocol": "openid-connect",
        "attributes": {
            "include.in.token.scope": in_token,
            "display.on.consent.screen": on_consent,
        },
    })
}

/// The `{id, name}` form of a client's scope lists.
fn brief(realm_id: &str, name: &str) -> Value {
    json!({ "id": scope_id(realm_id, name).to_string(), "name": name })
}

async fn list_scopes(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewClients).await?;
    let realm_id = realm_id(&state, &realm).await?;
    Ok(json_response(Value::Array(
        SCOPES
            .into_iter()
            .map(|scope| representation(&realm_id, scope))
            .collect(),
    )))
}

async fn read_scope(
    State(state): State<OidcState>,
    Path((realm, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewClients).await?;
    let realm_id = realm_id(&state, &realm).await?;
    SCOPES
        .into_iter()
        .find(|(name, ..)| scope_id(&realm_id, name).to_string() == id)
        .map(|scope| json_response(representation(&realm_id, scope)))
        .ok_or_else(|| {
            AdminError::Error(StatusCode::NOT_FOUND, "Could not find client scope".into())
        })
}

async fn realm_defaults(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewRealm).await?;
    let realm_id = realm_id(&state, &realm).await?;
    Ok(json_response(Value::Array(
        SCOPES
            .into_iter()
            .map(|(name, ..)| {
                let mut scope = brief(&realm_id, name);
                scope["protocol"] = json!("openid-connect");
                scope
            })
            .collect(),
    )))
}

async fn no_scopes(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewRealm).await?;
    realm_id(&state, &realm).await?;
    Ok(json_response(json!([])))
}

/// Resolves the realm and checks the client exists.
async fn client_realm(state: &OidcState, realm: &str, client: &str) -> Result<String, AdminError> {
    let realm_id = realm_id(state, realm).await?;
    state
        .storage
        .client(&realm_id, client)
        .await?
        .ok_or_else(|| AdminError::Error(StatusCode::NOT_FOUND, "Could not find client".into()))?;
    Ok(realm_id)
}

async fn client_defaults(
    State(state): State<OidcState>,
    Path((realm, client)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewClients).await?;
    let realm_id = client_realm(&state, &realm, &client).await?;
    Ok(json_response(Value::Array(
        SCOPES
            .into_iter()
            .map(|(name, ..)| brief(&realm_id, name))
            .collect(),
    )))
}

async fn client_optional(
    State(state): State<OidcState>,
    Path((realm, client)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewClients).await?;
    client_realm(&state, &realm, &client).await?;
    Ok(json_response(json!([])))
}

/// The names of every client's default scopes, for client representations.
pub(super) fn default_scope_names() -> Vec<&'static str> {
    SCOPES.into_iter().map(|(name, ..)| name).collect()
}
