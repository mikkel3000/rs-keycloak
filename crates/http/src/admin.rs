//! Keycloak admin REST routes for realms. Master `admin` tokens reach every
//! realm; a realm's own tokens reach that realm through its
//! `realm-management` roles.
//!
//! Responses follow the recorded 26.8.1 cases in
//! `tests/reference/admin-realm-observations.json`. Only the representation
//! fields stored today are accepted; other fields are refused instead of being
//! silently ignored.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rs_keycloak_storage_postgres::{
    AccessTokenStatus, Actor, MASTER_REALM, RealmCreation, RealmDeletion, RealmRecord,
    RealmSettings, RealmSmtp, StorageError,
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::oidc::{OidcState, digest, valid_realm, verified_access_any};

mod clients;
mod groups;
mod roles;
mod users;

/// Admin routes, mounted with the public routes below the issuer path.
pub(crate) fn routes() -> Router<OidcState> {
    Router::new()
        .merge(clients::routes())
        .merge(groups::routes())
        .merge(roles::routes())
        .merge(users::routes())
        .route("/admin/realms", post(create_realm).get(list_realms))
        .route(
            "/admin/realms/{realm}",
            get(read_realm).put(update_realm).delete(delete_realm),
        )
}

/// Admin API failures with the reference status and body shapes.
enum AdminError {
    /// Missing, invalid, revoked or sessionless-and-unknown token.
    Unauthorized,
    /// The token holder lacks the access the request needs.
    Forbidden,
    /// The named realm does not exist.
    RealmNotFound,
    /// A request error reported in an `errorMessage` body.
    Message(StatusCode, String),
    /// An error reported in an `error` body.
    Error(StatusCode, String),
    /// An OAuth-style `error` and `error_description` body.
    OAuth(StatusCode, &'static str, &'static str),
    /// Storage or signing capacity is unavailable.
    Unavailable,
}

impl AdminError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self::Message(StatusCode::BAD_REQUEST, message.into())
    }
}

impl From<StorageError> for AdminError {
    fn from(_: StorageError) -> Self {
        Self::Unavailable
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let error = |status, message: &str| (status, Json(json!({ "error": message })));
        match self {
            Self::Unauthorized => {
                error(StatusCode::UNAUTHORIZED, "HTTP 401 Unauthorized").into_response()
            }
            Self::Forbidden => error(StatusCode::FORBIDDEN, "HTTP 403 Forbidden").into_response(),
            Self::RealmNotFound => error(StatusCode::NOT_FOUND, "Realm not found.").into_response(),
            Self::Message(status, message) => {
                (status, Json(json!({ "errorMessage": message }))).into_response()
            }
            Self::Error(status, message) => error(status, &message).into_response(),
            Self::OAuth(status, code, description) => (
                status,
                Json(json!({ "error": code, "error_description": description })),
            )
                .into_response(),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::CACHE_CONTROL, "no-store")],
                "Service unavailable",
            )
                .into_response(),
        }
    }
}

/// What an admin request needs in its realm, following the recorded cases
/// in `tests/reference/admin-permission-observations.json`.
#[derive(Clone, Copy)]
enum Access {
    /// Any `realm-management` role, enough to read the realm's name.
    AnyRole,
    QueryUsers,
    ViewUsers,
    ManageUsers,
    QueryGroups,
    QueryClients,
    ViewClients,
    ManageClients,
    ViewRealm,
    ManageRealm,
}

impl Access {
    /// The `realm-management` roles that grant this access. `realm-admin`
    /// reaches every one through its composites.
    fn roles(self) -> &'static [&'static str] {
        match self {
            Self::AnyRole => &[],
            Self::QueryUsers => &["query-users", "view-users", "manage-users"],
            Self::ViewUsers => &["view-users", "manage-users"],
            Self::ManageUsers => &["manage-users"],
            Self::QueryGroups => &["query-groups", "view-users", "manage-users"],
            Self::QueryClients => &["query-clients", "view-clients", "manage-clients"],
            Self::ViewClients => &["view-clients", "manage-clients"],
            Self::ManageClients => &["manage-clients"],
            Self::ViewRealm => &["view-realm", "manage-realm"],
            Self::ManageRealm => &["manage-realm"],
        }
    }
}

/// What an authenticated admin may do in the requested realm.
enum Grants {
    /// A master `admin` reaches every realm.
    All,
    /// A token of the managed realm holds these effective
    /// `realm-management` roles.
    Roles(Vec<String>),
}

impl Grants {
    fn allows(&self, access: Access) -> bool {
        match self {
            Self::All => true,
            Self::Roles(roles) if matches!(access, Access::AnyRole) => !roles.is_empty(),
            Self::Roles(roles) => access
                .roles()
                .iter()
                .any(|needed| roles.iter().any(|role| role == needed)),
        }
    }
}

/// Resolves the bearer token to its live user, in the realm that issued it.
async fn token_holder(
    state: &OidcState,
    headers: &HeaderMap,
) -> Result<(String, Actor), AdminError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(AdminError::Unauthorized)?;
    let (realm, claims) = verified_access_any(state, token)
        .await
        .map_err(|()| AdminError::Unavailable)?
        .ok_or(AdminError::Unauthorized)?;
    let realm_id = state
        .storage
        .realm_id_by_name(&realm)
        .await?
        .ok_or(AdminError::Unauthorized)?;
    let user_id = match state
        .storage
        .active_access_token(
            &realm_id,
            &claims.azp,
            claims.sid.as_deref(),
            &claims.sub,
            &digest(&claims.jti),
        )
        .await?
    {
        AccessTokenStatus::Active(session) => session.user_id,
        AccessTokenStatus::ServiceAccount(account) => account.user_id,
        AccessTokenStatus::ClientNotFound
        | AccessTokenStatus::Revoked
        | AccessTokenStatus::SessionNotFound => return Err(AdminError::Unauthorized),
    };
    Ok((realm, Actor { realm_id, user_id }))
}

/// Resolves the bearer token and what it may do in the named realm. Only
/// master tokens reach other realms; any other realm's token is refused.
async fn admin(
    state: &OidcState,
    headers: &HeaderMap,
    realm: &str,
) -> Result<(Actor, Grants), AdminError> {
    let (token_realm, actor) = token_holder(state, headers).await?;
    let grants = grants(state, &token_realm, &actor, realm).await?;
    Ok((actor, grants))
}

/// What a token holder of `token_realm` may do in `realm`.
async fn grants(
    state: &OidcState,
    token_realm: &str,
    actor: &Actor,
    realm: &str,
) -> Result<Grants, AdminError> {
    Ok(if actor.realm_id == MASTER_REALM {
        if !state.storage.is_master_admin(&actor.user_id).await? {
            return Err(AdminError::Forbidden);
        }
        Grants::All
    } else if token_realm == realm {
        let mut roles = state
            .storage
            .effective_roles(&actor.realm_id, &actor.user_id)
            .await?;
        Grants::Roles(roles.clients.remove("realm-management").unwrap_or_default())
    } else {
        return Err(AdminError::Forbidden);
    })
}

/// Authorizes one kind of access to the named realm.
async fn authorize(
    state: &OidcState,
    headers: &HeaderMap,
    realm: &str,
    access: Access,
) -> Result<Actor, AdminError> {
    let (actor, grants) = admin(state, headers, realm).await?;
    if grants.allows(access) {
        Ok(actor)
    } else {
        Err(AdminError::Forbidden)
    }
}

/// Authorizes a master `admin`, the only one who creates or deletes realms.
async fn authorize_master(state: &OidcState, headers: &HeaderMap) -> Result<Actor, AdminError> {
    let (_, actor) = token_holder(state, headers).await?;
    if actor.realm_id != MASTER_REALM || !state.storage.is_master_admin(&actor.user_id).await? {
        return Err(AdminError::Forbidden);
    }
    Ok(actor)
}

/// The supported subset of a RealmRepresentation.
struct NewRealm {
    name: String,
    settings: RealmSettings,
}

/// Parses Keycloak's `smtpServer` object, whose values are strings. An empty
/// object removes the settings. SMTP authentication is refused until its
/// password can be stored sealed.
fn parse_smtp(value: &Value) -> Result<Option<RealmSmtp>, AdminError> {
    let Value::Object(fields) = value else {
        return Err(AdminError::bad_request(
            "unable to read contents from stream",
        ));
    };
    if fields.is_empty() {
        return Ok(None);
    }
    let text = |name: &str| match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) if value.len() <= 255 => Ok(Some(value.clone())),
        Some(_) => Err(AdminError::bad_request(format!(
            "Invalid smtpServer {name}"
        ))),
    };
    let flag = |name: &str| match text(name)?.as_deref() {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(AdminError::bad_request(format!(
            "Invalid smtpServer {name}"
        ))),
    };
    if let Some(field) = fields.keys().find(|key| {
        !matches!(
            key.as_str(),
            "host" | "port" | "from" | "fromDisplayName" | "starttls" | "ssl" | "auth"
        )
    }) {
        return Err(AdminError::bad_request(format!(
            "Unsupported smtpServer field: {field}"
        )));
    }
    if flag("auth")? {
        return Err(AdminError::bad_request(
            "Unsupported smtpServer field: auth",
        ));
    }
    let host = text("host")?.ok_or_else(|| AdminError::bad_request("Invalid smtpServer host"))?;
    let port = match text("port")? {
        None => 25,
        Some(port) => port
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .map(i32::from)
            .ok_or_else(|| AdminError::bad_request("Invalid smtpServer port"))?,
    };
    Ok(Some(RealmSmtp {
        host,
        port,
        from: text("from")?,
        from_display_name: text("fromDisplayName")?,
        starttls: flag("starttls")?,
        ssl: flag("ssl")?,
    }))
}

/// Keycloak's string-valued `smtpServer` representation.
fn smtp_representation(smtp: &RealmSmtp) -> Value {
    let mut fields = serde_json::Map::new();
    fields.insert("host".into(), json!(smtp.host));
    fields.insert("port".into(), json!(smtp.port.to_string()));
    if let Some(from) = &smtp.from {
        fields.insert("from".into(), json!(from));
    }
    if let Some(name) = &smtp.from_display_name {
        fields.insert("fromDisplayName".into(), json!(name));
    }
    if smtp.starttls {
        fields.insert("starttls".into(), json!("true"));
    }
    if smtp.ssl {
        fields.insert("ssl".into(), json!("true"));
    }
    Value::Object(fields)
}

/// Parses a creation body, refusing fields this server does not store yet.
fn parse_new_realm(body: &[u8]) -> Result<NewRealm, AdminError> {
    let unreadable = || AdminError::bad_request("unable to read contents from stream");
    let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(body) else {
        return Err(unreadable());
    };
    if let Some(field) = fields.keys().find(|key| {
        !matches!(
            key.as_str(),
            "realm" | "enabled" | "smtpServer" | "resetPasswordAllowed" | "verifyEmail"
        )
    }) {
        return Err(AdminError::bad_request(format!(
            "Unsupported realm field: {field}"
        )));
    }
    let name = match fields.get("realm") {
        None | Some(Value::Null) => "",
        Some(Value::String(name)) => name.as_str(),
        Some(_) => return Err(unreadable()),
    };
    if name.trim().is_empty() {
        return Err(AdminError::bad_request("Realm name cannot be empty"));
    }
    if !valid_realm(name) {
        return Err(AdminError::bad_request("Invalid realm name"));
    }
    let enabled = match fields.get("enabled") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(enabled)) => *enabled,
        Some(_) => return Err(unreadable()),
    };
    let smtp = match fields.get("smtpServer") {
        None | Some(Value::Null) => None,
        Some(value) => parse_smtp(value)?,
    };
    let flag = |name: &str| match fields.get(name) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(unreadable()),
    };
    Ok(NewRealm {
        name: name.to_owned(),
        settings: RealmSettings {
            enabled,
            reset_password_allowed: flag("resetPasswordAllowed")?,
            verify_email: flag("verifyEmail")?,
            smtp,
        },
    })
}

async fn create_realm(
    State(state): State<OidcState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AdminError> {
    let actor = authorize_master(&state, &headers).await?;
    let realm = parse_new_realm(&body)?;
    let created = state
        .storage
        .create_realm(
            &Uuid::new_v4().to_string(),
            &realm.name,
            &realm.settings,
            &actor,
        )
        .await?;
    match created {
        RealmCreation::Created => {
            let location = format!(
                "{}/admin/realms/{}",
                state.issuer_base.trim_end_matches('/'),
                realm.name
            );
            let location = HeaderValue::from_str(&location).map_err(|_| AdminError::Unavailable)?;
            Ok((StatusCode::CREATED, [(header::LOCATION, location)]).into_response())
        }
        RealmCreation::Exists => Err(AdminError::Message(
            StatusCode::CONFLICT,
            format!("Realm {} already exists", realm.name),
        )),
    }
}

async fn read_realm(
    State(state): State<OidcState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    let (_, grants) = admin(&state, &headers, &name).await?;
    if !grants.allows(Access::AnyRole) {
        return Err(AdminError::Forbidden);
    }
    let realm = state
        .storage
        .realm_by_name(&name)
        .await?
        .ok_or(AdminError::RealmNotFound)?;
    if !grants.allows(Access::ViewRealm) {
        // The reference's brief representation; only its field names were
        // recorded, and these values are the defaults this server has.
        let mut brief = json!({
            "realm": realm.name,
            "bruteForceProtected": false,
            "organizationsEnabled": false,
            "supportedLocales": [],
        });
        if grants.allows(Access::ViewUsers) {
            brief["registrationEmailAsUsername"] = json!(false);
        }
        return Ok(json_text(&brief));
    }
    Ok(json_text(&realm_representation(&realm)))
}

fn realm_representation(realm: &RealmRecord) -> Value {
    let mut representation = json!({ "id": realm.id, "realm": realm.name, "enabled": realm.enabled, "resetPasswordAllowed": realm.reset_password_allowed, "verifyEmail": realm.verify_email });
    if let Some(smtp) = &realm.smtp {
        representation["smtpServer"] = smtp_representation(smtp);
    }
    representation
}

/// Lists the realms a token reaches: every realm for a master `admin`, and
/// only its own realm, by name alone without `view-realm`, for a realm's
/// token.
async fn list_realms(
    State(state): State<OidcState>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    let (token_realm, actor) = token_holder(&state, &headers).await?;
    let grants = grants(&state, &token_realm, &actor, &token_realm).await?;
    let listed: Vec<Value> = match grants {
        Grants::All => state
            .storage
            .realms()
            .await?
            .iter()
            .map(realm_representation)
            .collect(),
        grants if grants.allows(Access::AnyRole) => {
            let realm = state
                .storage
                .realm_by_name(&token_realm)
                .await?
                .ok_or(AdminError::Unauthorized)?;
            if grants.allows(Access::ViewRealm) {
                vec![realm_representation(&realm)]
            } else {
                vec![json!({ "realm": realm.name })]
            }
        }
        _ => return Err(AdminError::Forbidden),
    };
    Ok(json_text(&Value::Array(listed)))
}

/// A JSON body with the reference's content type.
fn json_text(value: &Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json;charset=UTF-8")],
        value.to_string(),
    )
        .into_response()
}

/// Applies a partial realm representation of the stored settings.
async fn update_realm(
    State(state): State<OidcState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers, &name, Access::ManageRealm).await?;
    let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(&body) else {
        return Err(AdminError::bad_request(
            "unable to read contents from stream",
        ));
    };
    if let Some(field) = fields.keys().find(|key| {
        !matches!(
            key.as_str(),
            "realm" | "enabled" | "smtpServer" | "resetPasswordAllowed" | "verifyEmail"
        )
    }) {
        return Err(AdminError::bad_request(format!(
            "Unsupported realm field: {field}"
        )));
    }
    if fields
        .get("realm")
        .is_some_and(|realm| realm != &json!(name))
    {
        return Err(AdminError::bad_request("Renaming realms is not supported"));
    }
    let enabled = match fields.get("enabled") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(enabled)) => Some(*enabled),
        Some(_) => {
            return Err(AdminError::bad_request(
                "unable to read contents from stream",
            ));
        }
    };
    let smtp = fields.get("smtpServer").map(parse_smtp).transpose()?;
    let optional_flag = |name: &str| match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(AdminError::bad_request(
            "unable to read contents from stream",
        )),
    };
    let reset_password_allowed = optional_flag("resetPasswordAllowed")?;
    let verify_email = optional_flag("verifyEmail")?;
    if state
        .storage
        .update_realm(
            &name,
            enabled,
            reset_password_allowed,
            verify_email,
            smtp.as_ref().map(Option::as_ref),
            &actor,
        )
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AdminError::RealmNotFound)
    }
}

async fn delete_realm(
    State(state): State<OidcState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let actor = authorize_master(&state, &headers).await?;
    match state.storage.delete_realm(&name, &actor).await? {
        RealmDeletion::Deleted => Ok(StatusCode::NO_CONTENT),
        RealmDeletion::NotFound => Err(AdminError::RealmNotFound),
        RealmDeletion::Master => Err(AdminError::bad_request("Can't remove master realm")),
    }
}
