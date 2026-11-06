//! Admin REST routes for OpenID Connect clients within a realm.
//!
//! Follows the recorded cases in `tests/reference/admin-client-observations.json`
//! and `tests/reference/admin-client-update-observations.json`.
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
use rs_keycloak_protocols::client_urls::{
    validate_redirect_pattern, validate_root_url, validate_web_origin,
};
use rs_keycloak_storage_postgres::{
    Actor, ClientCreation, ClientRecord, ClientUpdate, NewClient, SealedSecret, SecretChange,
    client_secret_context,
};
use serde_json::{Map, Value, json};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::users::{
    json_object, json_response, realm_id, representation as user_representation, unparsable,
};
use super::{Access, AdminError, authorize};
use crate::oidc::{OidcState, random_token};

pub(super) fn routes() -> Router<OidcState> {
    Router::new()
        .route(
            "/admin/realms/{realm}/clients",
            post(create_client).get(list_clients),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}",
            get(read_client).put(update_client).delete(delete_client),
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

/// Reads a string list, or `None` when the field is absent.
fn string_list(fields: &Map<String, Value>, name: &str) -> Result<Option<Vec<String>>, AdminError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) if values.len() <= 64 => values
            .iter()
            .map(|value| match value {
                Value::String(value) => Ok(value.clone()),
                _ => Err(unparsable()),
            })
            .collect::<Result<_, _>>()
            .map(Some),
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
fn client_attributes(attributes: &Value) -> Result<(Vec<String>, bool), AdminError> {
    let Value::Object(attributes) = attributes else {
        return Err(unparsable());
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
                        validate_redirect_pattern(uri, false).map_err(AdminError::bad_request)?;
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

pub(super) fn representation(client: &ClientRecord, secret: Option<String>) -> Value {
    let mut fields = json!({
        "id": client.id,
        "clientId": client.client_identifier,
        "enabled": client.enabled,
        "clientAuthenticatorType": "client-secret",
        "redirectUris": client.redirect_uris,
        "webOrigins": client.web_origins,
        "bearerOnly": client.bearer_only,
        "standardFlowEnabled": client.standard_flow,
        "implicitFlowEnabled": false,
        "directAccessGrantsEnabled": false,
        "serviceAccountsEnabled": client.service_accounts,
        "consentRequired": client.consent_required,
        "publicClient": client.public,
        "protocol": "openid-connect",
    });
    if let Some(secret) = secret {
        fields["secret"] = json!(secret);
    }
    fields["defaultClientScopes"] = json!(super::client_scopes::default_scope_names());
    fields["optionalClientScopes"] = json!([]);
    if let Some(root_url) = &client.root_url {
        fields["rootUrl"] = json!(root_url);
    }
    if let Some(base_url) = &client.base_url {
        fields["baseUrl"] = json!(base_url);
    }
    fields
}

/// Request fields a client representation may carry here; the rest are
/// refused rather than ignored.
const SUPPORTED: [&str; 17] = [
    "rootUrl",
    "baseUrl",
    "consentRequired",
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

/// Client settings, from the creation defaults or a stored client, with a
/// request's fields applied on top.
struct Settings {
    enabled: bool,
    public: bool,
    standard_flow: bool,
    service_accounts: bool,
    bearer_only: bool,
    consent_required: bool,
    redirect_uris: Vec<String>,
    web_origins: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    post_logout_uses_redirect_uris: bool,
    root_url: Option<String>,
    base_url: Option<String>,
}

impl Settings {
    /// The reference defaults: a confidential client with standard flow.
    fn defaults() -> Self {
        Self {
            enabled: true,
            public: false,
            standard_flow: true,
            service_accounts: false,
            bearer_only: false,
            consent_required: false,
            redirect_uris: Vec::new(),
            web_origins: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            post_logout_uses_redirect_uris: false,
            root_url: None,
            base_url: None,
        }
    }

    fn stored(client: &ClientRecord) -> Self {
        Self {
            enabled: client.enabled,
            public: client.public,
            standard_flow: client.standard_flow,
            service_accounts: client.service_accounts,
            bearer_only: client.bearer_only,
            consent_required: client.consent_required,
            redirect_uris: client.redirect_uris.clone(),
            web_origins: client.web_origins.clone(),
            post_logout_redirect_uris: client.post_logout_redirect_uris.clone(),
            post_logout_uses_redirect_uris: client.post_logout_uses_redirect_uris,
            root_url: client.root_url.clone(),
            base_url: client.base_url.clone(),
        }
    }

    /// Applies and validates the fields present; absent fields keep their
    /// value, as reference updates do.
    fn apply(mut self, fields: &Map<String, Value>, allowed: &[&str]) -> Result<Self, AdminError> {
        if let Some(field) = fields
            .keys()
            .find(|key| !SUPPORTED.contains(&key.as_str()) && !allowed.contains(&key.as_str()))
        {
            return Err(AdminError::bad_request(format!(
                "Unsupported client field: {field}"
            )));
        }
        require_value(fields, "protocol", &json!("openid-connect"))?;
        require_value(fields, "clientAuthenticatorType", &json!("client-secret"))?;
        for excluded in ["directAccessGrantsEnabled", "implicitFlowEnabled"] {
            require_value(fields, excluded, &json!(false))?;
        }
        self.enabled = bool_field(fields, "enabled", self.enabled)?;
        self.public = bool_field(fields, "publicClient", self.public)?;
        self.standard_flow = bool_field(fields, "standardFlowEnabled", self.standard_flow)?;
        self.service_accounts =
            bool_field(fields, "serviceAccountsEnabled", self.service_accounts)?;
        self.bearer_only = bool_field(fields, "bearerOnly", self.bearer_only)?;
        self.consent_required = bool_field(fields, "consentRequired", self.consent_required)?;
        if self.public && self.service_accounts {
            return Err(AdminError::bad_request(
                "Public clients cannot use service accounts",
            ));
        }
        for (name, value) in [
            ("rootUrl", &mut self.root_url),
            ("baseUrl", &mut self.base_url),
        ] {
            match fields.get(name) {
                None => (),
                Some(Value::Null) => *value = None,
                Some(Value::String(url)) if url.is_empty() => *value = None,
                Some(Value::String(url)) if url.len() <= 2048 => *value = Some(url.clone()),
                Some(_) => return Err(AdminError::bad_request(format!("Invalid {name}"))),
            }
        }
        if let Some(root_url) = &self.root_url {
            validate_root_url(root_url, false).map_err(AdminError::bad_request)?;
        }
        if let Some(base_url) = &self.base_url {
            validate_redirect_pattern(base_url, false).map_err(AdminError::bad_request)?;
        }
        if let Some(uris) = string_list(fields, "redirectUris")? {
            for uri in &uris {
                validate_redirect_pattern(uri, false).map_err(AdminError::bad_request)?;
            }
            self.redirect_uris = uris;
        }
        if self.root_url.is_none() && self.redirect_uris.iter().any(|uri| uri.starts_with('/')) {
            return Err(AdminError::bad_request(
                "Relative redirect URIs require a rootUrl",
            ));
        }
        if let Some(origins) = string_list(fields, "webOrigins")? {
            for origin in &origins {
                validate_web_origin(origin, false).map_err(AdminError::bad_request)?;
            }
            self.web_origins = origins;
        }
        if let Some(attributes) = fields.get("attributes").filter(|value| !value.is_null()) {
            (
                self.post_logout_redirect_uris,
                self.post_logout_uses_redirect_uris,
            ) = client_attributes(attributes)?;
        }
        Ok(self)
    }

    fn client<'a>(&'a self, client_identifier: &'a str) -> NewClient<'a> {
        NewClient {
            client_identifier,
            enabled: self.enabled,
            public: self.public,
            standard_flow: self.standard_flow,
            service_accounts: self.service_accounts,
            bearer_only: self.bearer_only,
            redirect_uris: &self.redirect_uris,
            web_origins: &self.web_origins,
            post_logout_redirect_uris: &self.post_logout_redirect_uris,
            post_logout_uses_redirect_uris: self.post_logout_uses_redirect_uris,
            consent_required: self.consent_required,
            root_url: self.root_url.as_deref(),
            base_url: self.base_url.as_deref(),
        }
    }
}

/// Reads a requested `clientId`, or `None` when the field is absent.
fn client_identifier(fields: &Map<String, Value>) -> Result<Option<String>, AdminError> {
    match fields.get("clientId") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() && value.len() <= 255 => {
            Ok(Some(value.clone()))
        }
        Some(_) => Err(AdminError::bad_request("Invalid clientId")),
    }
}

/// Reads a requested secret, or `None` when the field is absent.
fn requested_secret(fields: &Map<String, Value>) -> Result<Option<Zeroizing<String>>, AdminError> {
    match fields.get("secret") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(secret)) if (32..=1024).contains(&secret.len()) => {
            Ok(Some(Zeroizing::new(secret.clone())))
        }
        Some(_) => Err(AdminError::bad_request(
            "Client secret must be 32-1024 bytes",
        )),
    }
}

/// The origins of redirect URIs, which the reference gives a new client
/// created without web origins.
fn redirect_origins(redirect_uris: &[String]) -> Vec<String> {
    let mut origins: Vec<String> = redirect_uris
        .iter()
        .filter_map(|uri| Url::parse(uri).ok())
        .map(|uri| uri.origin().ascii_serialization())
        .filter(|origin| validate_web_origin(origin, false).is_ok())
        .collect();
    origins.sort();
    origins.dedup();
    origins
}

async fn create_client(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageClients).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let fields = json_object(&body)?;
    let id = create_from(&state, &realm_id, &fields, &actor).await?;
    let location = format!(
        "{}/admin/realms/{realm}/clients/{id}",
        state.issuer_base.trim_end_matches('/')
    );
    let location = HeaderValue::from_str(&location).map_err(|_| AdminError::Unavailable)?;
    Ok((StatusCode::CREATED, [(header::LOCATION, location)]).into_response())
}

/// Creates a client from a representation; returns its internal id.
pub(super) async fn create_from(
    state: &OidcState,
    realm_id: &str,
    fields: &Map<String, Value>,
    actor: &Actor,
) -> Result<String, AdminError> {
    let mut settings = Settings::defaults().apply(fields, &[])?;
    if !fields.contains_key("webOrigins") {
        settings.web_origins = redirect_origins(&settings.redirect_uris);
    }
    let id = Uuid::new_v4().to_string();
    // The reference generates a client identifier when none is given.
    let client_identifier = client_identifier(fields)?.unwrap_or_else(|| id.clone());
    let secret = match (settings.public, requested_secret(fields)?) {
        (true, None) => None,
        (true, Some(_)) => {
            return Err(AdminError::bad_request(
                "Public clients cannot have a secret",
            ));
        }
        (false, None) => Some(seal(state, realm_id, &id, random_token().as_bytes())?),
        (false, Some(secret)) => Some(seal(state, realm_id, &id, secret.as_bytes())?),
    };
    let created = state
        .storage
        .create_client(
            realm_id,
            &id,
            &settings.client(&client_identifier),
            secret.as_ref(),
            &Uuid::new_v4().to_string(),
            actor,
        )
        .await?;
    match created {
        ClientCreation::Created => Ok(id),
        ClientCreation::Exists => Err(AdminError::Message(
            StatusCode::CONFLICT,
            format!("Client {client_identifier} already exists"),
        )),
    }
}

/// Applies a partial representation; a body `id` is ignored, as the
/// reference ignores it.
async fn update_client(
    State(state): State<OidcState>,
    Path((realm, id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageClients).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let stored = state
        .storage
        .client(&realm_id, &id)
        .await?
        .ok_or_else(client_not_found)?;
    let fields = json_object(&body)?;
    update_from(&state, &realm_id, stored, &fields, &actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Applies a partial representation to a stored client; a body `id` is
/// ignored.
pub(super) async fn update_from(
    state: &OidcState,
    realm_id: &str,
    stored: ClientRecord,
    fields: &Map<String, Value>,
    actor: &Actor,
) -> Result<(), AdminError> {
    let id = stored.id.clone();
    let settings = Settings::stored(&stored).apply(fields, &["id"])?;
    let client_identifier = client_identifier(fields)?.unwrap_or(stored.client_identifier);
    let sealed = match (settings.public, requested_secret(fields)?) {
        (true, Some(_)) => {
            return Err(AdminError::bad_request(
                "Public clients cannot have a secret",
            ));
        }
        (true, None) => None,
        (false, Some(secret)) => Some(seal(state, realm_id, &id, secret.as_bytes())?),
        // A client that becomes confidential gets a new secret.
        (false, None) if stored.public => {
            Some(seal(state, realm_id, &id, random_token().as_bytes())?)
        }
        (false, None) => None,
    };
    let secret = match (&sealed, settings.public && !stored.public) {
        (Some(sealed), _) => SecretChange::Replace(sealed),
        (None, true) => SecretChange::Remove,
        (None, false) => SecretChange::Keep,
    };
    let updated = state
        .storage
        .update_client(
            realm_id,
            &id,
            &settings.client(&client_identifier),
            secret,
            &Uuid::new_v4().to_string(),
            actor,
        )
        .await?;
    match updated {
        ClientUpdate::Updated => Ok(()),
        ClientUpdate::NotFound => Err(client_not_found()),
        ClientUpdate::Exists => Err(AdminError::OAuth(
            StatusCode::CONFLICT,
            "conflict",
            "Duplicate resource error",
        )),
    }
}

async fn list_clients(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::QueryClients).await?;
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
    authorize(&state, &headers, &realm, Access::ViewClients).await?;
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
    authorize(&state, &headers, &realm, Access::ViewClients).await?;
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
    let actor = authorize(&state, &headers, &realm, Access::ManageClients).await?;
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
    authorize(&state, &headers, &realm, Access::ViewClients).await?;
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
    let actor = authorize(&state, &headers, &realm, Access::ManageClients).await?;
    let realm_id = realm_id(&state, &realm).await?;
    if state.storage.delete_client(&realm_id, &id, &actor).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(client_not_found())
    }
}
