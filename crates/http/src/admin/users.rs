//! Admin REST routes for users within a realm.
//!
//! Follows the recorded cases in `tests/reference/admin-user-observations.json`.
//! Usernames and emails are stored lowercased, as the reference does. Fields
//! and search parameters that are not modelled yet are refused.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use rs_keycloak_storage_postgres::{
    Actor, Collision, NewPassword, NewUser, UserCreation, UserQuery, UserRecord, UserUpdate,
};
use serde_json::{Map, Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{Access, AdminError, FieldError, authorize};
use crate::mail::valid_email;
use crate::oidc::{OidcState, digest, random_token};

/// Keycloak's default page size for user searches.
const DEFAULT_MAX_RESULTS: i64 = 100;
/// Longest password the login path accepts.
const MAX_PASSWORD_BYTES: usize = 1024;

pub(super) fn routes() -> Router<OidcState> {
    Router::new()
        .route(
            "/admin/realms/{realm}/users",
            post(create_user).get(search_users),
        )
        .route("/admin/realms/{realm}/users/count", get(count_users))
        .route(
            "/admin/realms/{realm}/users/{user}",
            get(read_user).put(update_user).delete(delete_user),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/reset-password",
            put(reset_password),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/consents",
            get(list_consents),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/execute-actions-email",
            put(execute_actions_email),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/send-verify-email",
            put(send_verify_email),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/credentials",
            get(list_credentials),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/credentials/{credential}",
            delete(delete_credential),
        )
        .route(
            "/admin/realms/{realm}/users/{user}/consents/{client}",
            delete(revoke_consent),
        )
}

fn user_not_found() -> AdminError {
    AdminError::Error(StatusCode::NOT_FOUND, "User not found".into())
}

pub(super) fn unparsable() -> AdminError {
    AdminError::OAuth(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Cannot parse the JSON",
    )
}

/// Resolves the realm identifier for an existing realm name.
pub(super) async fn realm_id(state: &OidcState, name: &str) -> Result<String, AdminError> {
    state
        .storage
        .realm_by_name(name)
        .await?
        .map(|realm| realm.id)
        .ok_or(AdminError::RealmNotFound)
}

/// Parses a JSON object body or reports the reference parse error.
pub(super) fn json_object(body: &[u8]) -> Result<Map<String, Value>, AdminError> {
    match serde_json::from_slice(body) {
        Ok(Value::Object(fields)) => Ok(fields),
        _ => Err(unparsable()),
    }
}

/// Reads an optional string field, lowercased if requested.
fn text(fields: &Map<String, Value>, name: &str) -> Result<Option<String>, AdminError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.trim().is_empty() => Ok(None),
        Some(Value::String(value)) if value.len() <= 255 && !value.contains(char::is_control) => {
            Ok(Some(value.trim().to_owned()))
        }
        Some(Value::String(_)) => Err(AdminError::bad_request(format!("Invalid {name}"))),
        Some(_) => Err(unparsable()),
    }
}

fn flag(fields: &Map<String, Value>, name: &str, default: bool) -> Result<bool, AdminError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(unparsable()),
    }
}

pub(super) fn representation(user: UserRecord) -> Value {
    let mut fields = Map::new();
    fields.insert("id".into(), json!(user.id));
    fields.insert("username".into(), json!(user.username));
    if let Some(first_name) = user.first_name {
        fields.insert("firstName".into(), json!(first_name));
    }
    if let Some(last_name) = user.last_name {
        fields.insert("lastName".into(), json!(last_name));
    }
    if let Some(email) = user.email {
        fields.insert("email".into(), json!(email));
    }
    fields.insert("emailVerified".into(), json!(user.email_verified));
    fields.insert("createdTimestamp".into(), json!(user.created_timestamp));
    fields.insert("enabled".into(), json!(user.enabled));
    fields.insert("totp".into(), json!(user.totp));
    fields.insert(
        "disableableCredentialTypes".into(),
        json!(if user.totp { vec!["otp"] } else { Vec::new() }),
    );
    fields.insert("requiredActions".into(), json!(user.required_actions));
    fields.insert("notBefore".into(), json!(0));
    // Permanent lockout's reason is the one attribute kept, as the
    // reference's disabledReason.
    if let Some(reason) = user.disabled_reason {
        fields.insert("attributes".into(), json!({ "disabledReason": [reason] }));
    }
    Value::Object(fields)
}

pub(super) fn json_response(value: Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json;charset=UTF-8")],
        value.to_string(),
    )
        .into_response()
}

/// User fields this server stores, from the creation defaults or a stored
/// user, with a request's fields applied on top.
struct UserSettings {
    email: Option<String>,
    email_verified: bool,
    first_name: Option<String>,
    last_name: Option<String>,
    enabled: bool,
    required_actions: Vec<String>,
}

impl UserSettings {
    fn defaults() -> Self {
        Self {
            email: None,
            email_verified: false,
            first_name: None,
            last_name: None,
            enabled: false,
            required_actions: Vec::new(),
        }
    }

    fn stored(user: &UserRecord) -> Self {
        Self {
            email: user.email.clone(),
            email_verified: user.email_verified,
            first_name: user.first_name.clone(),
            last_name: user.last_name.clone(),
            enabled: user.enabled,
            required_actions: user.required_actions.clone(),
        }
    }

    /// Applies the fields present; an empty name or email removes it, and
    /// absent fields keep their value, as reference updates do.
    fn apply(mut self, fields: &Map<String, Value>, allowed: &[&str]) -> Result<Self, AdminError> {
        const SUPPORTED: [&str; 7] = [
            "requiredActions",
            "username",
            "enabled",
            "email",
            "emailVerified",
            "firstName",
            "lastName",
        ];
        if let Some(field) = fields
            .keys()
            .find(|key| !SUPPORTED.contains(&key.as_str()) && !allowed.contains(&key.as_str()))
        {
            return Err(AdminError::bad_request(format!(
                "Unsupported user field: {field}"
            )));
        }
        if fields.contains_key("email") {
            self.email = text(fields, "email")?.map(|email| email.to_lowercase());
        }
        if fields.contains_key("firstName") {
            self.first_name = text(fields, "firstName")?;
        }
        if fields.contains_key("lastName") {
            self.last_name = text(fields, "lastName")?;
        }
        self.email_verified = flag(fields, "emailVerified", self.email_verified)?;
        self.enabled = flag(fields, "enabled", self.enabled)?;
        match fields.get("requiredActions") {
            None | Some(Value::Null) => (),
            Some(Value::Array(actions)) => {
                self.required_actions = actions
                    .iter()
                    .map(|action| match action {
                        Value::String(action)
                            if matches!(
                                action.as_str(),
                                "CONFIGURE_TOTP" | "UPDATE_PASSWORD" | "UPDATE_PROFILE"
                            ) =>
                        {
                            Ok(action.clone())
                        }
                        Value::String(action) => Err(AdminError::bad_request(format!(
                            "Unsupported required action: {action}"
                        ))),
                        _ => Err(unparsable()),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            }
            Some(_) => return Err(unparsable()),
        }
        Ok(self)
    }

    /// The reference's error for a malformed email, naming the sent value.
    fn email_error(&self, fields: &Map<String, Value>) -> Option<AdminError> {
        let email = self.email.as_deref()?;
        if valid_email(email) {
            return None;
        }
        let sent = match fields.get("email") {
            Some(Value::String(sent)) => sent.clone(),
            _ => email.to_owned(),
        };
        Some(AdminError::field(
            "email",
            "error-invalid-email",
            vec!["email".into(), sent],
        ))
    }

    fn user<'a>(&'a self, username: &'a str) -> NewUser<'a> {
        NewUser {
            required_actions: &self.required_actions,
            username,
            email: self.email.as_deref(),
            email_verified: self.email_verified,
            first_name: self.first_name.as_deref(),
            last_name: self.last_name.as_deref(),
            enabled: self.enabled,
        }
    }
}

fn email_exists() -> AdminError {
    AdminError::Message(StatusCode::CONFLICT, "User exists with same email".into())
}

/// The reference's answer when its email lookup finds several users.
fn shared_email() -> AdminError {
    AdminError::Message(
        StatusCode::CONFLICT,
        "User exists with same username or email".into(),
    )
}

async fn create_user(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let fields = json_object(&body)?;
    let user_id = create_from(&state, &realm_id, &fields, &actor).await?;
    let location = format!(
        "{}/admin/realms/{realm}/users/{user_id}",
        state.issuer_base.trim_end_matches('/')
    );
    let location = HeaderValue::from_str(&location).map_err(|_| AdminError::Unavailable)?;
    Ok((StatusCode::CREATED, [(header::LOCATION, location)]).into_response())
}

/// Creates a user from a representation; returns the user's id.
pub(super) async fn create_from(
    state: &OidcState,
    realm_id: &str,
    fields: &Map<String, Value>,
    actor: &Actor,
) -> Result<String, AdminError> {
    let settings = UserSettings::defaults().apply(fields, &["credentials"])?;
    // A realm that uses the email as username takes the email when given.
    let email_as_username = state
        .storage
        .user_settings(realm_id)
        .await?
        .registration_email_as_username;
    let email = if email_as_username {
        text(fields, "email")?
    } else {
        None
    };
    let username = email
        .or(text(fields, "username")?)
        .ok_or_else(|| AdminError::bad_request("User name is missing"))?
        .to_lowercase();
    // As in the reference, a missing username, then a taken username or
    // email answers before the field errors.
    match state
        .storage
        .new_user_collision(realm_id, &username, settings.email.as_deref())
        .await?
    {
        Collision::None => (),
        Collision::Username => {
            return Err(AdminError::Message(
                StatusCode::CONFLICT,
                "User exists with same username".into(),
            ));
        }
        Collision::Email => return Err(email_exists()),
        Collision::SharedEmail => return Err(shared_email()),
    }
    if let Some(error) = settings.email_error(fields) {
        return Err(error);
    }
    let password = match initial_password(fields)? {
        Some(credential) => Some(hashed_password(state, credential).await?),
        None => None,
    };
    let user_id = Uuid::new_v4().to_string();
    let credential_id = Uuid::new_v4().to_string();
    let password = password.as_ref().map(|(hash, temporary)| NewPassword {
        credential_id: &credential_id,
        phc: hash.as_bytes(),
        temporary: *temporary,
    });
    match state
        .storage
        .create_user(
            realm_id,
            &user_id,
            &settings.user(&username),
            password.as_ref(),
            actor,
        )
        .await?
    {
        UserCreation::Created => Ok(user_id),
        UserCreation::UsernameExists => Err(AdminError::Message(
            StatusCode::CONFLICT,
            "User exists with same username".into(),
        )),
        UserCreation::EmailExists => Err(email_exists()),
    }
}

/// Applies a partial representation under the realm's username rules; a
/// body `id` is ignored.
async fn update_user(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let stored = state
        .storage
        .user(&realm_id, &user)
        .await?
        .ok_or_else(user_not_found)?;
    let fields = json_object(&body)?;
    update_from(&state, &realm_id, &stored, &fields, &actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Applies a partial representation to a stored user under the realm's
/// username rules, as the pinned user profile does for the admin API and
/// `tests/reference/login-settings-observations.json` records. When the
/// email is the username, the username follows the email and a sent one is
/// ignored; otherwise a sent username changes only with
/// `editUsernameAllowed`. The reference collects every error, then answers
/// with the first missing username, taken username or taken email, else
/// with the field errors.
pub(super) async fn update_from(
    state: &OidcState,
    realm_id: &str,
    stored: &UserRecord,
    fields: &Map<String, Value>,
    actor: &Actor,
) -> Result<(), AdminError> {
    let settings = UserSettings::stored(stored).apply(fields, &["id"])?;
    let rules = state.storage.user_settings(realm_id).await?;
    let missing = || AdminError::bad_request("User name is missing");
    let username = if rules.registration_email_as_username {
        settings.email.clone().ok_or_else(missing)?
    } else {
        match fields.get("username") {
            None | Some(Value::Null) => stored.username.clone(),
            Some(_) => text(fields, "username")?
                .ok_or_else(missing)?
                .to_lowercase(),
        }
    };
    let mut errors = Vec::new();
    if !rules.registration_email_as_username
        && !rules.edit_username_allowed
        && username != stored.username
    {
        errors.push(FieldError {
            field: "username",
            message: "error-user-attribute-read-only",
            params: vec!["username".into()],
        });
    }
    if let Some(AdminError::Fields(email)) = settings.email_error(fields) {
        errors.extend(email);
    }
    let checked = state
        .storage
        .update_user(
            realm_id,
            &stored.id,
            &settings.user(&username),
            errors.is_empty(),
            actor,
        )
        .await?;
    match checked {
        UserUpdate::Updated => Ok(()),
        UserUpdate::NotFound => Err(user_not_found()),
        // When the email is the username, the reference reports the
        // collision on the email.
        UserUpdate::UsernameExists if rules.registration_email_as_username => Err(email_exists()),
        UserUpdate::UsernameExists => Err(AdminError::Message(
            StatusCode::CONFLICT,
            "User exists with same username".into(),
        )),
        UserUpdate::EmailExists => Err(email_exists()),
        UserUpdate::SharedEmail => Err(shared_email()),
        UserUpdate::Checked => Err(AdminError::Fields(errors)),
    }
}

/// Escapes a value for a SQL `LIKE` pattern with `\` as the escape.
pub(super) fn like_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.to_lowercase().chars() {
        if matches!(character, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

/// The reference's `search`: a quoted value matches exactly, `*` is a
/// wildcard, and anything else matches as a prefix.
fn search_pattern(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(exact) = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        return Some(like_literal(exact));
    }
    let pattern = value
        .split('*')
        .map(like_literal)
        .collect::<Vec<_>>()
        .join("%");
    Some(if value.contains('*') {
        pattern
    } else {
        pattern + "%"
    })
}

/// Search filters as stored patterns: text fields match infix, or
/// exactly under `exact=true`.
struct SearchPatterns {
    search: Option<String>,
    username: Option<String>,
    email: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    enabled: Option<bool>,
    email_verified: Option<bool>,
}

impl SearchPatterns {
    fn parse(params: &HashMap<String, String>, allowed: &[&str]) -> Result<Self, AdminError> {
        const FILTERS: [&str; 8] = [
            "search",
            "username",
            "email",
            "firstName",
            "lastName",
            "enabled",
            "emailVerified",
            "exact",
        ];
        if let Some(name) = params
            .keys()
            .find(|name| !FILTERS.contains(&name.as_str()) && !allowed.contains(&name.as_str()))
        {
            return Err(AdminError::bad_request(format!(
                "Unsupported user search parameter: {name}"
            )));
        }
        let exact = params.get("exact").is_some_and(|value| value == "true");
        let text = |name: &str| {
            params
                .get(name)
                .filter(|value| !value.is_empty())
                .map(|value| {
                    let literal = like_literal(value);
                    if exact {
                        literal
                    } else {
                        format!("%{literal}%")
                    }
                })
        };
        let boolean = |name: &str| match params.get(name).map(String::as_str) {
            None => Ok(None),
            Some("true") => Ok(Some(true)),
            Some("false") => Ok(Some(false)),
            Some(_) => Err(AdminError::bad_request(format!("Invalid {name}"))),
        };
        let search = params.get("search").and_then(|value| search_pattern(value));
        Ok(Self {
            // The reference applies `search` instead of `username`.
            username: if params.contains_key("search") {
                None
            } else {
                text("username")
            },
            search,
            email: text("email"),
            first_name: text("firstName"),
            last_name: text("lastName"),
            enabled: boolean("enabled")?,
            email_verified: boolean("emailVerified")?,
        })
    }

    fn query(&self) -> UserQuery<'_> {
        UserQuery {
            search: self.search.as_deref(),
            username: self.username.as_deref(),
            email: self.email.as_deref(),
            first_name: self.first_name.as_deref(),
            last_name: self.last_name.as_deref(),
            enabled: self.enabled,
            email_verified: self.email_verified,
        }
    }
}

async fn search_users(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::QueryUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let patterns = SearchPatterns::parse(&params, &["first", "max", "briefRepresentation"])?;
    let number = |name: &str, default: i64| match params.get(name) {
        None => Ok(default),
        Some(value) => value
            .parse::<i64>()
            .ok()
            .filter(|value| *value >= 0)
            .ok_or_else(|| AdminError::bad_request(format!("Invalid {name}"))),
    };
    let first = number("first", 0)?;
    let max = number("max", DEFAULT_MAX_RESULTS)?.min(DEFAULT_MAX_RESULTS * 10);
    let brief = params
        .get("briefRepresentation")
        .is_some_and(|value| value == "true");
    let users = state
        .storage
        .search_users(&realm_id, &patterns.query(), first, max)
        .await?;
    Ok(json_response(Value::Array(
        users
            .into_iter()
            .map(|user| {
                let mut fields = representation(user);
                if brief {
                    // The brief form leaves out credential and action fields.
                    if let Some(fields) = fields.as_object_mut() {
                        for field in [
                            "totp",
                            "disableableCredentialTypes",
                            "requiredActions",
                            "notBefore",
                        ] {
                            fields.remove(field);
                        }
                    }
                }
                fields
            })
            .collect(),
    )))
}

async fn count_users(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::QueryUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let patterns = SearchPatterns::parse(&params, &[])?;
    Ok(json_response(json!(
        state
            .storage
            .count_users(&realm_id, &patterns.query())
            .await?
    )))
}

async fn read_user(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let user = state
        .storage
        .user(&realm_id, &user)
        .await?
        .ok_or_else(user_not_found)?;
    Ok(json_response(representation(user)))
}

async fn delete_user(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    if state.storage.delete_user(&realm_id, &user, &actor).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(user_not_found())
    }
}

/// The password among a new user's `credentials`, the last one when there
/// are several, as in the reference. Any other credential type refuses the
/// whole creation.
fn initial_password(
    fields: &Map<String, Value>,
) -> Result<Option<&Map<String, Value>>, AdminError> {
    let credentials = match fields.get("credentials") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Array(credentials)) => credentials,
        Some(_) => return Err(unparsable()),
    };
    let mut password = None;
    for credential in credentials {
        let Value::Object(credential) = credential else {
            return Err(unparsable());
        };
        if let Some(field) = credential
            .keys()
            .find(|key| !matches!(key.as_str(), "type" | "value" | "temporary"))
        {
            return Err(AdminError::bad_request(format!(
                "Unsupported credential field: {field}"
            )));
        }
        match credential.get("type") {
            None | Some(Value::Null) => (),
            Some(Value::String(kind)) if kind == "password" => (),
            Some(_) => return Err(AdminError::bad_request("Could not create user")),
        }
        password = Some(credential);
    }
    Ok(password)
}

/// Reads and hashes a password credential: `type` must be absent or
/// `password`, `value` non-empty, and `temporary` defaults to false.
async fn hashed_password(
    state: &OidcState,
    fields: &Map<String, Value>,
) -> Result<(Zeroizing<String>, bool), AdminError> {
    match fields.get("type") {
        None | Some(Value::Null) => (),
        Some(Value::String(kind)) if kind == "password" => (),
        Some(_) => {
            return Err(AdminError::bad_request(
                "Only password credentials are supported",
            ));
        }
    }
    let temporary = flag(fields, "temporary", false)?;
    let password = match fields.get("value") {
        Some(Value::String(value)) if !value.is_empty() => Zeroizing::new(value.clone()),
        None | Some(Value::Null | Value::String(_)) => {
            return Err(AdminError::Error(
                StatusCode::BAD_REQUEST,
                "Empty password not allowed".into(),
            ));
        }
        Some(_) => return Err(unparsable()),
    };
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(AdminError::bad_request(
            "Password must be at most 1024 bytes",
        ));
    }
    let permit = Arc::clone(&state.hash_slots)
        .try_acquire_owned()
        .map_err(|_| AdminError::Unavailable)?;
    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        rs_keycloak_crypto::hash_password(password.as_bytes())
    })
    .await
    .map_err(|_| AdminError::Unavailable)?
    .map(Zeroizing::new)
    .map_err(|_| AdminError::Unavailable)?;
    Ok((hash, temporary))
}

async fn reset_password(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers, &realm, Access::ManageUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let fields = json_object(&body)?;
    if let Some(field) = fields
        .keys()
        .find(|key| !matches!(key.as_str(), "type" | "value" | "temporary"))
    {
        return Err(AdminError::bad_request(format!(
            "Unsupported credential field: {field}"
        )));
    }
    // Check the user before spending hashing work on an unknown identifier.
    if state.storage.user(&realm_id, &user).await?.is_none() {
        return Err(user_not_found());
    }
    let (hash, temporary) = hashed_password(&state, &fields).await?;
    let changed = state
        .storage
        .reset_password(
            &realm_id,
            &user,
            &Uuid::new_v4().to_string(),
            hash.as_bytes(),
            temporary,
            &actor,
        )
        .await?;
    if changed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(user_not_found())
    }
}

async fn list_consents(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let consents = state
        .storage
        .user_consents(&realm_id, &user)
        .await?
        .ok_or_else(user_not_found)?;
    let listed = consents
        .into_iter()
        .map(|consent| {
            json!({
                "clientId": consent.client_identifier,
                "grantedClientScopes": consent.scope.split(' ').filter(|scope| !scope.is_empty()).collect::<Vec<_>>(),
                "createdDate": consent.created,
                "lastUpdatedDate": consent.updated,
                "additionalGrants": [],
            })
        })
        .collect();
    Ok(json_response(Value::Array(listed)))
}

async fn revoke_consent(
    State(state): State<OidcState>,
    Path((realm, user, client)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    authorize(&state, &headers, &realm, Access::ManageUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    // The pinned UserResource reports an unknown client before the consent.
    if state
        .storage
        .clients(&realm_id, Some(&client))
        .await?
        .is_empty()
    {
        return Err(AdminError::Error(
            StatusCode::NOT_FOUND,
            "Client not found".into(),
        ));
    }
    if state
        .storage
        .revoke_consent(&realm_id, &user, &client)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AdminError::Error(
            StatusCode::NOT_FOUND,
            "Consent nor offline token not found".into(),
        ))
    }
}

async fn list_credentials(
    State(state): State<OidcState>,
    Path((realm, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let credentials = state
        .storage
        .user_credentials(&realm_id, &user)
        .await?
        .ok_or_else(user_not_found)?;
    let listed = credentials
        .into_iter()
        .map(|credential| {
            // Secrets and seeds are never returned, only algorithm parameters.
            // OTP data keeps OTPCredentialData's field order.
            let data = if credential.credential_type == "otp" {
                let otp = &credential.otp;
                format!(
                    "{{\"subType\":{},\"digits\":{},\"counter\":{},\"period\":{},\"algorithm\":{}}}",
                    json!(otp.kind),
                    otp.digits.unwrap_or_default(),
                    otp.counter.unwrap_or_default(),
                    otp.period.unwrap_or_default(),
                    json!(otp.algorithm),
                )
            } else {
                json!({"algorithm":"argon2"}).to_string()
            };
            let mut fields = json!({
                "id": credential.id,
                "type": credential.credential_type,
                "createdDate": credential.created,
                "credentialData": data,
            });
            if let Some(label) = credential.user_label {
                fields["userLabel"] = json!(label);
            }
            fields
        })
        .collect();
    Ok(json_response(Value::Array(listed)))
}

async fn delete_credential(
    State(state): State<OidcState>,
    Path((realm, user, credential)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    authorize(&state, &headers, &realm, Access::ManageUsers).await?;
    let realm_id = realm_id(&state, &realm).await?;
    if state
        .storage
        .delete_credential(&realm_id, &user, &credential)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AdminError::Error(
            StatusCode::NOT_FOUND,
            "Credential not found".into(),
        ))
    }
}

/// Required actions Keycloak defines; others are rejected as invalid.
const KNOWN_ACTIONS: [&str; 8] = [
    "CONFIGURE_TOTP",
    "TERMS_AND_CONDITIONS",
    "UPDATE_PASSWORD",
    "UPDATE_PROFILE",
    "VERIFY_EMAIL",
    "delete_account",
    "update_user_locale",
    "webauthn-register",
];

/// Default lifespan of an admin-sent action link, as in Keycloak (12 hours).
const ACTION_LINK_SECONDS: i32 = 43_200;

/// Emails the user a single-use link to perform required actions.
async fn execute_actions_email(
    State(state): State<OidcState>,
    Path((realm_name, user)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    authorize(&state, &headers, &realm_name, Access::ManageUsers).await?;
    let realm = state
        .storage
        .realm_by_name(&realm_name)
        .await?
        .ok_or(AdminError::RealmNotFound)?;
    let user = state
        .storage
        .user(&realm.id, &user)
        .await?
        .ok_or_else(user_not_found)?;
    let email = user
        .email
        .ok_or_else(|| AdminError::bad_request("User email missing"))?;
    let Ok(Value::Array(requested)) = serde_json::from_slice::<Value>(&body) else {
        return Err(unparsable());
    };
    let mut actions = Vec::new();
    for action in &requested {
        match action.as_str() {
            Some(name) if KNOWN_ACTIONS.contains(&name) => actions.push(name.to_owned()),
            _ => return Err(AdminError::bad_request("Provided invalid required actions")),
        }
    }
    if let Some(unsupported) = actions
        .iter()
        .find(|action| action.as_str() != "UPDATE_PASSWORD")
    {
        return Err(AdminError::bad_request(format!(
            "Unsupported required action: {unsupported}"
        )));
    }
    if actions.is_empty() {
        return Err(AdminError::bad_request("Provided invalid required actions"));
    }
    let lifespan = match params.get("lifespan") {
        None => ACTION_LINK_SECONDS,
        Some(value) => value
            .parse::<i32>()
            .ok()
            .filter(|seconds| *seconds > 0)
            .ok_or_else(|| AdminError::bad_request("Invalid lifespan"))?,
    };
    // The reference reports a missing sender as a delivery failure.
    let settings = crate::mail::settings(&realm).ok_or_else(|| AdminError::Message(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to send execute actions email: Invalid sender address 'null'. If the address contains UTF-8 characters in the local part please ensure the SMTP server supports the SMTPUTF8 extension and enable 'Allow UTF-8' in the email realm configuration.".into(),
    ))?;
    let token = Zeroizing::new(random_token());
    if !state
        .storage
        .issue_action_token(
            &realm.id,
            &user.id,
            &digest(&token),
            &actions,
            lifespan,
            None,
        )
        .await?
    {
        return Err(user_not_found());
    }
    let link = crate::mail::action_link(&state, &realm.name, &token);
    let recipient = crate::mail::Recipient {
        email: &email,
        locale: user.locale.as_deref(),
    };
    // The admin's own headers do not choose the user's language.
    match crate::mail::deliver(
        &state,
        &realm,
        &settings,
        &recipient,
        &HeaderMap::new(),
        &crate::mail::Template::ExecuteActions(&actions),
        &link,
        lifespan,
    )
    .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(_) => Err(AdminError::Message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to send execute actions email".into(),
        )),
    }
}

/// Emails the user a link that verifies their address.
async fn send_verify_email(
    State(state): State<OidcState>,
    Path((realm_name, user)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    authorize(&state, &headers, &realm_name, Access::ManageUsers).await?;
    let realm = state
        .storage
        .realm_by_name(&realm_name)
        .await?
        .ok_or(AdminError::RealmNotFound)?;
    let user = state
        .storage
        .user(&realm.id, &user)
        .await?
        .ok_or_else(user_not_found)?;
    let email = user
        .email
        .ok_or_else(|| AdminError::bad_request("User email missing"))?;
    let lifespan = match params.get("lifespan") {
        None => ACTION_LINK_SECONDS,
        Some(value) => value
            .parse::<i32>()
            .ok()
            .filter(|seconds| *seconds > 0)
            .ok_or_else(|| AdminError::bad_request("Invalid lifespan"))?,
    };
    let failed = || {
        AdminError::Message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to send verify email".into(),
        )
    };
    let settings = crate::mail::settings(&realm).ok_or_else(failed)?;
    let token = Zeroizing::new(random_token());
    let actions = ["VERIFY_EMAIL".to_owned()];
    if !state
        .storage
        .issue_action_token(
            &realm.id,
            &user.id,
            &digest(&token),
            &actions,
            lifespan,
            None,
        )
        .await?
    {
        return Err(user_not_found());
    }
    let link = crate::mail::action_link(&state, &realm.name, &token);
    let recipient = crate::mail::Recipient {
        email: &email,
        locale: user.locale.as_deref(),
    };
    crate::mail::deliver(
        &state,
        &realm,
        &settings,
        &recipient,
        &HeaderMap::new(),
        &crate::mail::Template::EmailVerification,
        &link,
        lifespan,
    )
    .await
    .map_err(|_| failed())?;
    Ok(StatusCode::NO_CONTENT)
}
