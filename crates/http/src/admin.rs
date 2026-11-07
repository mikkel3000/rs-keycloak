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
    AccessTokenStatus, Actor, MASTER_REALM, RealmChanges, RealmCreation, RealmDeletion,
    RealmRecord, RealmSettings, RealmSmtp, StorageError, UserSettingChanges, UserSettings,
};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::oidc::{OidcState, digest, valid_realm, verified_access_any};

mod authentication;
mod client_scopes;
mod clients;
mod export;
mod groups;
mod roles;
mod sessions;
mod users;

/// Admin routes, mounted with the public routes below the issuer path.
pub(crate) fn routes() -> Router<OidcState> {
    Router::new()
        .merge(authentication::routes())
        .merge(client_scopes::routes())
        .merge(clients::routes())
        .merge(export::routes())
        .merge(groups::routes())
        .merge(roles::routes())
        .merge(sessions::routes())
        .merge(users::routes())
        .route("/admin/realms", post(create_realm).get(list_realms))
        .route("/admin/realms/{realm}/keys", get(realm_keys))
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
    /// A 400 for representation fields, as the reference's user profile
    /// reports them: one error alone as its `field`, `errorMessage` and
    /// `params`, several in an `errors` list.
    Fields(Vec<FieldError>),
    /// An error reported in an `error` body.
    Error(StatusCode, String),
    /// An OAuth-style `error` and `error_description` body.
    OAuth(StatusCode, &'static str, &'static str),
    /// Storage or signing capacity is unavailable.
    Unavailable,
}

/// One user profile error on a representation field.
struct FieldError {
    field: &'static str,
    message: &'static str,
    params: Vec<String>,
}

impl FieldError {
    fn body(&self) -> Value {
        json!({ "field": self.field, "errorMessage": self.message, "params": self.params })
    }
}

impl AdminError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self::Message(StatusCode::BAD_REQUEST, message.into())
    }

    /// One field error with the reference's message parameters.
    fn field(field: &'static str, message: &'static str, params: Vec<String>) -> Self {
        Self::Fields(vec![FieldError {
            field,
            message,
            params,
        }])
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
            Self::Fields(errors) => {
                let body = match errors.as_slice() {
                    [error] => error.body(),
                    errors => {
                        json!({ "errors": errors.iter().map(FieldError::body).collect::<Vec<_>>() })
                    }
                };
                (StatusCode::BAD_REQUEST, Json(body)).into_response()
            }
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
/// Reads `displayName`: `None` when absent, `Some(None)` to remove it. An
/// empty name is kept, as in the reference.
fn display_name(fields: &Map<String, Value>) -> Result<Option<Option<String>>, AdminError> {
    match fields.get("displayName") {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(Value::String(name)) if name.len() <= 255 && !name.contains(char::is_control) => {
            Ok(Some(Some(name.clone())))
        }
        Some(_) => Err(AdminError::bad_request("Invalid displayName")),
    }
}

/// Reads `accessTokenLifespan` in seconds. The reference also stores zero
/// and negative values, which only yield expired tokens; they are refused.
fn access_token_lifespan(fields: &Map<String, Value>) -> Result<Option<i32>, AdminError> {
    match fields.get("accessTokenLifespan") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number
            .as_i64()
            .and_then(|seconds| i32::try_from(seconds).ok())
            .filter(|seconds| *seconds > 0)
            .map(Some)
            .ok_or_else(|| AdminError::bad_request("Invalid accessTokenLifespan")),
        Some(_) => Err(AdminError::OAuth(
            StatusCode::BAD_REQUEST,
            "unknown_error",
            "Cannot parse the JSON",
        )),
    }
}

/// Realm fields this server stores besides the name.
const REALM_FIELDS: [&str; 12] = [
    "enabled",
    "smtpServer",
    "resetPasswordAllowed",
    "verifyEmail",
    "displayName",
    "accessTokenLifespan",
    "internationalizationEnabled",
    "supportedLocales",
    "defaultLocale",
    "editUsernameAllowed",
    "registrationEmailAsUsername",
    "realm",
];

/// The locale and username settings a realm representation carries;
/// absent and null fields are `None`.
#[derive(Default)]
struct UserSettingFields {
    internationalization_enabled: Option<bool>,
    supported_locales: Option<Vec<String>>,
    default_locale: Option<String>,
    edit_username_allowed: Option<bool>,
    registration_email_as_username: Option<bool>,
}

impl UserSettingFields {
    /// Reads the fields; a value of the wrong JSON type fails as the
    /// reference's JSON reader does. Locales are stored sorted, without
    /// repeats.
    fn parse(fields: &Map<String, Value>) -> Result<Self, AdminError> {
        let unparsable = || {
            AdminError::OAuth(
                StatusCode::BAD_REQUEST,
                "unknown_error",
                "Cannot parse the JSON",
            )
        };
        let flag = |name: &str| match fields.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(value)) => Ok(Some(*value)),
            Some(_) => Err(unparsable()),
        };
        let locale = |value: &Value| match value {
            Value::String(tag) if tag.len() <= 255 => Ok(tag.clone()),
            Value::String(_) => Err(AdminError::bad_request("Invalid locale")),
            _ => Err(unparsable()),
        };
        let supported_locales = match fields.get("supportedLocales") {
            None | Some(Value::Null) => None,
            Some(Value::Array(tags)) if tags.len() <= 200 => {
                let mut tags = tags.iter().map(locale).collect::<Result<Vec<_>, _>>()?;
                tags.sort();
                tags.dedup();
                Some(tags)
            }
            Some(Value::Array(_)) => return Err(AdminError::bad_request("Too many locales")),
            Some(_) => return Err(unparsable()),
        };
        let default_locale = match fields.get("defaultLocale") {
            None | Some(Value::Null) => None,
            Some(value) => Some(locale(value)?),
        };
        Ok(Self {
            internationalization_enabled: flag("internationalizationEnabled")?,
            supported_locales,
            default_locale,
            edit_username_allowed: flag("editUsernameAllowed")?,
            registration_email_as_username: flag("registrationEmailAsUsername")?,
        })
    }

    fn changes(&self) -> UserSettingChanges<'_> {
        UserSettingChanges {
            internationalization_enabled: self.internationalization_enabled,
            supported_locales: self.supported_locales.as_deref(),
            default_locale: self.default_locale.as_deref(),
            edit_username_allowed: self.edit_username_allowed,
            registration_email_as_username: self.registration_email_as_username,
        }
    }

    fn settings(self) -> UserSettings {
        UserSettings {
            internationalization_enabled: self.internationalization_enabled.unwrap_or(false),
            supported_locales: self.supported_locales.unwrap_or_default(),
            default_locale: self.default_locale,
            edit_username_allowed: self.edit_username_allowed.unwrap_or(false),
            registration_email_as_username: self.registration_email_as_username.unwrap_or(false),
        }
    }
}

fn unsupported_realm_field(fields: &Map<String, Value>) -> Result<(), AdminError> {
    match fields
        .keys()
        .find(|key| !REALM_FIELDS.contains(&key.as_str()))
    {
        Some(field) => Err(AdminError::bad_request(format!(
            "Unsupported realm field: {field}"
        ))),
        None => Ok(()),
    }
}

fn parse_new_realm(body: &[u8]) -> Result<NewRealm, AdminError> {
    let unreadable = || AdminError::bad_request("unable to read contents from stream");
    let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(body) else {
        return Err(unreadable());
    };
    unsupported_realm_field(&fields)?;
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
            display_name: display_name(&fields)?.flatten(),
            access_token_lifespan: access_token_lifespan(&fields)?.unwrap_or(300),
            user_settings: UserSettingFields::parse(&fields)?.settings(),
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
            "supportedLocales": realm.user_settings.supported_locales,
        });
        if grants.allows(Access::ViewUsers) {
            brief["registrationEmailAsUsername"] =
                json!(realm.user_settings.registration_email_as_username);
        }
        if let Some(display_name) = &realm.display_name {
            brief["displayName"] = json!(display_name);
        }
        return Ok(json_text(&brief));
    }
    Ok(json_text(&realm_representation(&realm)))
}

fn realm_representation(realm: &RealmRecord) -> Value {
    let mut representation = json!({ "id": realm.id, "realm": realm.name, "enabled": realm.enabled, "resetPasswordAllowed": realm.reset_password_allowed, "verifyEmail": realm.verify_email, "accessTokenLifespan": realm.access_token_lifespan });
    if let Some(display_name) = &realm.display_name {
        representation["displayName"] = json!(display_name);
    }
    if let Some(smtp) = &realm.smtp {
        representation["smtpServer"] = smtp_representation(smtp);
    }
    let users = &realm.user_settings;
    representation["internationalizationEnabled"] = json!(users.internationalization_enabled);
    if !users.supported_locales.is_empty() {
        representation["supportedLocales"] = json!(users.supported_locales);
    }
    if let Some(locale) = &users.default_locale {
        representation["defaultLocale"] = json!(locale);
    }
    representation["editUsernameAllowed"] = json!(users.edit_username_allowed);
    representation["registrationEmailAsUsername"] = json!(users.registration_email_as_username);
    representation
}

/// The realm's keys, following `tests/reference/realm-key-observations.json`.
/// Every realm signs with the one operator-provided RS256 key, which has no
/// certificate or key provider component here.
async fn realm_keys(
    State(state): State<OidcState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &name, Access::ViewRealm).await?;
    state
        .storage
        .realm_by_name(&name)
        .await?
        .ok_or(AdminError::RealmNotFound)?;
    let kid = state.signer.key_id();
    Ok(json_text(&json!({
        "active": { "RS256": kid },
        "keys": [{
            "kid": kid,
            "type": "RSA",
            "algorithm": "RS256",
            "use": "SIG",
            "status": "ACTIVE",
            "providerPriority": 100,
            "publicKey": state.signer.public_key_info(),
        }],
    })))
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
    unsupported_realm_field(&fields)?;
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
    let display_name = display_name(&fields)?;
    let user_settings = UserSettingFields::parse(&fields)?;
    let changes = RealmChanges {
        enabled,
        reset_password_allowed: optional_flag("resetPasswordAllowed")?,
        verify_email: optional_flag("verifyEmail")?,
        smtp: smtp.as_ref().map(Option::as_ref),
        display_name: display_name.as_ref().map(Option::as_deref),
        access_token_lifespan: access_token_lifespan(&fields)?,
        user_settings: user_settings.changes(),
    };
    if state.storage.update_realm(&name, &changes, &actor).await? {
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
