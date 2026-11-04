//! Admin REST routes for OpenID Connect clients within a realm.
//!
//! Follows the recorded cases in `tests/reference/admin-client-observations.json`.
//! Confidential clients created here get secrets sealed with the operator
//! key, so the secret can be returned later as the reference does. Settings
//! for excluded or unmodelled features are refused, not ignored.

use std::collections::HashMap;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use rs_keycloak_protocols::client_urls::{validate_redirect_uri, validate_web_origin};
use rs_keycloak_storage_postgres::{
    ClientCreation, ClientRecord, NewClient, SealedSecret, client_secret_context,
};
use serde_json::{Map, Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::users::{
    json_object, json_response, realm_id, representation as user_representation, unparsable,
};
use super::{AdminError, authorize};
use crate::oidc::{OidcState, random_token};

pub(super) fn routes() -> Router<OidcState> {
    Router::new()
        .route(
            "/admin/realms/{realm}/clients",
            post(create_client).get(list_clients),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}",
            get(read_client).delete(delete_client),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/client-secret",
            get(read_secret).post(regenerate_secret),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/service-account-user",
            get(service_account_user),
        )
}

fn client_not_found() -> AdminError {
    AdminError::Error(StatusCode::NOT_FOUND, "Could not find client".into())
}

fn bool_field(fields: &Map<String, Value>, name: &str, default: bool) -> Result<bool, AdminError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(unparsable()),
    }
}

fn string_list(fields: &Map<String, Value>, name: &str) -> Result<Vec<String>, AdminError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) if values.len() <= 64 => values
            .iter()
            .map(|value| match value {
                Value::String(value) => Ok(value.clone()),
                _ => Err(unparsable()),
            })
            .collect(),
        Some(_) => Err(unparsable()),
    }
}

/// Rejects a setting unless it has the only value this server supports.
fn require_value(
    fields: &Map<String, Value>,
    name: &str,
    supported: &Value,
) -> Result<(), AdminError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(()),
        Some(value) if value == supported => Ok(()),
        Some(_) => Err(AdminError::bad_request(format!(
            "Unsupported client setting: {name}"
        ))),
    }
}

/// Reads the supported client attributes: PKCE, which is always S256, and
/// post-logout redirect URIs as a `##`-separated list, where `+` stands for
/// the client's redirect URIs.
fn client_attributes(attributes: Option<&Value>) -> Result<(Vec<String>, bool), AdminError> {
    let attributes = match attributes {
        None | Some(Value::Null) => return Ok((Vec::new(), false)),
        Some(Value::Object(attributes)) => attributes,
        Some(_) => return Err(unparsable()),
    };
    let mut uris = Vec::new();
    let mut uses_redirects = false;
    for (key, value) in attributes {
        match (key.as_str(), value) {
            ("pkce.code.challenge.method", Value::String(method)) if method == "S256" => (),
            ("post.logout.redirect.uris", Value::String(list)) => {
                for uri in list.split("##").filter(|uri| !uri.is_empty()) {
                    if uri == "+" {
                        uses_redirects = true;
                    } else {
                        validate_redirect_uri(uri, false).map_err(AdminError::bad_request)?;
                        uris.push(uri.to_owned());
                    }
                }
            }
            _ => {
                return Err(AdminError::bad_request(format!(
                    "Unsupported client attribute: {key}"
                )));
            }
        }
    }
    Ok((uris, uses_redirects))
}

/// Seals a secret for one client row with the operator key.
fn seal(
    state: &OidcState,
    realm_id: &str,
    id: &str,
    secret: &[u8],
) -> Result<SealedSecret, AdminError> {
    let key = state.secret_key.as_ref().ok_or_else(|| {
        AdminError::Message(
            StatusCode::SERVICE_UNAVAILABLE,
            "Confidential clients require RS_KEYCLOAK_SECRET_KEY".into(),
        )
    })?;
    let sealed = key
        .seal(secret, &client_secret_context(realm_id, id))
        .map_err(|_| AdminError::Unavailable)?;
    Ok(SealedSecret {
        sealed,
        key_id: key.key_id().to_owned(),
    })
}

/// Opens a client's sealed secret; hashed legacy secrets cannot be returned.
fn open(
    state: &OidcState,
    realm_id: &str,
    client: &ClientRecord,
) -> Result<Option<String>, AdminError> {
    let Some(secret) = &client.secret else {
        return Ok(None);
    };
    let key = state
        .secret_key
        .as_ref()
        .filter(|key| key.key_id() == secret.key_id)
        .ok_or(AdminError::Unavailable)?;
    let opened = key
        .open(&secret.sealed, &client_secret_context(realm_id, &client.id))
        .map_err(|_| AdminError::Unavailable)?;
    String::from_utf8(opened.to_vec())
        .map(Some)
        .map_err(|_| AdminError::Unavailable)
}

fn representation(client: &ClientRecord, secret: Option<String>) -> Value {
    let mut fields = json!({
        "id": client.id,
        "clientId": client.client_identifier,
        "enabled": client.enabled,
        "clientAuthenticatorType": "client-secret",
        "redirectUris": client.redirect_uris,
        "webOrigins": client.web_origins,
        "bearerOnly": false,
        "standardFlowEnabled": client.standard_flow,
        "implicitFlowEnabled": false,
        "directAccessGrantsEnabled": false,
        "serviceAccountsEnabled": client.service_accounts,
        "publicClient": client.public,
        "protocol": "openid-connect",
    });
    if let Some(secret) = secret {
        fields["secret"] = json!(secret);
    }
    fields
}

async fn create_client(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AdminError> {
    let actor = authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let fields = json_object(&body)?;
    const SUPPORTED: [&str; 14] = [
        "clientId",
        "enabled",
        "publicClient",
        "secret",
        "serviceAccountsEnabled",
        "standardFlowEnabled",
        "redirectUris",
        "webOrigins",
        "protocol",
        "clientAuthenticatorType",
        "directAccessGrantsEnabled",
        "implicitFlowEnabled",
        "bearerOnly",
        "attributes",
    ];
    if let Some(field) = fields.keys().find(|key| !SUPPORTED.contains(&key.as_str())) {
        return Err(AdminError::bad_request(format!(
            "Unsupported client field: {field}"
        )));
    }
    require_value(&fields, "protocol", &json!("openid-connect"))?;
    require_value(&fields, "clientAuthenticatorType", &json!("client-secret"))?;
    for excluded in [
        "directAccessGrantsEnabled",
        "implicitFlowEnabled",
        "bearerOnly",
    ] {
        require_value(&fields, excluded, &json!(false))?;
    }
    let (post_logout_redirect_uris, post_logout_uses_redirect_uris) =
        client_attributes(fields.get("attributes"))?;
    let id = Uuid::new_v4().to_string();
    // The reference generates a client identifier when none is given.
    let client_identifier = match fields.get("clientId") {
        None | Some(Value::Null) => id.clone(),
        Some(Value::String(value)) if !value.is_empty() && value.len() <= 255 => value.clone(),
        Some(_) => return Err(AdminError::bad_request("Invalid clientId")),
    };
    let public = bool_field(&fields, "publicClient", false)?;
    let service_accounts = bool_field(&fields, "serviceAccountsEnabled", false)?;
    if public && service_accounts {
        return Err(AdminError::bad_request(
            "Public clients cannot use service accounts",
        ));
    }
    let redirect_uris = string_list(&fields, "redirectUris")?;
    for uri in &redirect_uris {
        validate_redirect_uri(uri, false).map_err(AdminError::bad_request)?;
    }
    let web_origins = string_list(&fields, "webOrigins")?;
    for origin in &web_origins {
        validate_web_origin(origin, false).map_err(AdminError::bad_request)?;
    }
    let secret = match (public, fields.get("secret")) {
        (true, None | Some(Value::Null)) => None,
        (true, Some(_)) => {
            return Err(AdminError::bad_request(
                "Public clients cannot have a secret",
            ));
        }
        (false, None | Some(Value::Null)) => {
            Some(seal(&state, &realm_id, &id, random_token().as_bytes())?)
        }
        (false, Some(Value::String(secret))) if (32..=1024).contains(&secret.len()) => {
            let secret = Zeroizing::new(secret.clone());
            Some(seal(&state, &realm_id, &id, secret.as_bytes())?)
        }
        (false, Some(_)) => {
            return Err(AdminError::bad_request(
                "Client secret must be 32-1024 bytes",
            ));
        }
    };
    let client = NewClient {
        client_identifier: &client_identifier,
        enabled: bool_field(&fields, "enabled", true)?,
        public,
        standard_flow: bool_field(&fields, "standardFlowEnabled", true)?,
        service_accounts,
        redirect_uris: &redirect_uris,
        web_origins: &web_origins,
        post_logout_redirect_uris: &post_logout_redirect_uris,
        post_logout_uses_redirect_uris,
    };
    let created = state
        .storage
        .create_client(
            &realm_id,
            &id,
            &client,
            secret.as_ref(),
            &Uuid::new_v4().to_string(),
            &actor,
        )
        .await?;
    match created {
        ClientCreation::Created => {
            let location = format!(
                "{}/admin/realms/{realm}/clients/{id}",
                state.issuer_base.trim_end_matches('/')
            );
            let location = HeaderValue::from_str(&location).map_err(|_| AdminError::Unavailable)?;
            Ok((StatusCode::CREATED, [(header::LOCATION, location)]).into_response())
        }
        ClientCreation::Exists => Err(AdminError::Message(
            StatusCode::CONFLICT,
            format!("Client {client_identifier} already exists"),
        )),
    }
}

async fn list_clients(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    if let Some(name) = params.keys().find(|name| name.as_str() != "clientId") {
        return Err(AdminError::bad_request(format!(
            "Unsupported client search parameter: {name}"
        )));
    }
    let clients = state
        .storage
        .clients(&realm_id, params.get("clientId").map(String::as_str))
        .await?;
    let mut listed = Vec::with_capacity(clients.len());
    for client in &clients {
        listed.push(representation(client, open(&state, &realm_id, client)?));
    }
    Ok(json_response(Value::Array(listed)))
}

async fn find_client(
    state: &OidcState,
    realm_id: &str,
    id: &str,
) -> Result<ClientRecord, AdminError> {
    state
        .storage
        .client(realm_id, id)
        .await?
        .ok_or_else(client_not_found)
}

async fn read_client(
    State(state): State<OidcState>,
    Path((realm, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let client = find_client(&state, &realm_id, &id).await?;
    let secret = open(&state, &realm_id, &client)?;
    Ok(json_response(representation(&client, secret)))
}

async fn read_secret(
    State(state): State<OidcState>,
    Path((realm, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let client = find_client(&state, &realm_id, &id).await?;
    let mut credential = json!({ "type": "secret" });
    if let Some(secret) = open(&state, &realm_id, &client)? {
        credential["value"] = json!(secret);
    }
    Ok(json_response(credential))
}

async fn regenerate_secret(
    State(state): State<OidcState>,
    Path((realm, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    let actor = authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let client = find_client(&state, &realm_id, &id).await?;
    if client.public {
        return Err(AdminError::bad_request("Public clients have no secret"));
    }
    let secret = Zeroizing::new(random_token());
    let sealed = seal(&state, &realm_id, &client.id, secret.as_bytes())?;
    if !state
        .storage
        .replace_client_secret(&realm_id, &client.id, &sealed, &actor)
        .await?
    {
        return Err(client_not_found());
    }
    Ok(json_response(json!({ "type": "secret", "value": *secret })))
}

async fn service_account_user(
    State(state): State<OidcState>,
    Path((realm, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let client = find_client(&state, &realm_id, &id).await?;
    let Some(user_id) = state
        .storage
        .service_account_user_id(&realm_id, &client.id)
        .await?
    else {
        return Err(AdminError::Error(
            StatusCode::BAD_REQUEST,
            format!(
                "Service account not enabled for the client '{}'",
                client.client_identifier
            ),
        ));
    };
    let user = state
        .storage
        .user(&realm_id, &user_id)
        .await?
        .ok_or(AdminError::Unavailable)?;
    Ok(json_response(user_representation(user)))
}

async fn delete_client(
    State(state): State<OidcState>,
    Path((realm, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    if state.storage.delete_client(&realm_id, &id, &actor).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(client_not_found())
    }
}
