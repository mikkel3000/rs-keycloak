//! Keycloak's account REST API: a user's own profile, credentials and
//! sessions, authorized by their realm access token.
//!
//! Follows `tests/reference/account-api-observations.json` and
//! `tests/reference/account-console-api-observations.json`. Access follows the
//! user's effective roles of the built-in `account` client, which users
//! receive through the realm's default role: reading needs `view-profile` or
//! `manage-account`, changes need `manage-account`.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use rs_keycloak_storage_postgres::{
    AccessTokenStatus, AccountChange, Profile, StorageError, UserSettings,
};
use serde_json::{Map, Value, json};

use rs_keycloak_protocols::client_urls::resolve_redirect;

use crate::oidc::{OidcState, digest, verified_access};

/// Account routes, mounted with the public routes below the issuer path.
/// With the console configured, browser navigation to any of them, which
/// sends no JSON media type, gets the console page instead.
pub(crate) fn routes(state: OidcState) -> Router<OidcState> {
    Router::new()
        .route(
            "/realms/{realm}/account",
            get(read_profile).post(update_profile),
        )
        .route(
            "/realms/{realm}/account/",
            get(read_profile).post(update_profile),
        )
        .route("/realms/{realm}/account/credentials", get(credentials))
        .route(
            "/realms/{realm}/account/sessions",
            get(sessions).delete(end_other_sessions),
        )
        .route("/realms/{realm}/account/sessions/devices", get(devices))
        .route("/realms/{realm}/account/applications", get(applications))
        .route(
            "/realms/{realm}/account/applications/{client}/consent",
            delete(revoke_application),
        )
        .route(
            "/realms/{realm}/account/sessions/{session}",
            delete(end_session),
        )
        .route(
            "/realms/{realm}/account/supportedLocales",
            get(supported_locales),
        )
        .route(
            "/realms/{realm}/account/linked-accounts",
            get(linked_accounts),
        )
        .route("/realms/{realm}/account/groups", get(groups))
        .route_layer(axum::middleware::from_fn_with_state(
            state,
            crate::account_console::navigation,
        ))
}

/// Account API failures with the reference body shapes.
enum AccountError {
    Unauthorized,
    Forbidden,
    NotFound,
    /// A profile field failed validation.
    Field(StatusCode, &'static str, &'static str),
    /// Profile fields failed validation, as field and message pairs in the
    /// reference's order.
    Fields(StatusCode, Vec<(&'static str, &'static str)>),
    Unavailable,
}

/// One validation error; the parameter is the field's display name.
fn field_error(field: &str, message: &str) -> Value {
    json!({ "field": field, "errorMessage": message, "params": [format!("${{{field}}}")] })
}

impl From<StorageError> for AccountError {
    fn from(_: StorageError) -> Self {
        Self::Unavailable
    }
}

impl IntoResponse for AccountError {
    fn into_response(self) -> Response {
        let error = |status, message: &str| (status, Json(json!({ "error": message })));
        match self {
            Self::Unauthorized => {
                error(StatusCode::UNAUTHORIZED, "HTTP 401 Unauthorized").into_response()
            }
            Self::Forbidden => error(StatusCode::FORBIDDEN, "HTTP 403 Forbidden").into_response(),
            Self::NotFound => error(StatusCode::NOT_FOUND, "HTTP 404 Not Found").into_response(),
            Self::Field(status, field, message) => {
                Self::Fields(status, vec![(field, message)]).into_response()
            }
            // A single error is also given at the top level.
            Self::Fields(status, errors) => {
                let details: Vec<Value> = errors
                    .iter()
                    .map(|(field, message)| field_error(field, message))
                    .collect();
                let mut body = match details.as_slice() {
                    [single] => single.clone(),
                    _ => json!({}),
                };
                body["errors"] = Value::Array(details);
                (status, Json(body)).into_response()
            }
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::CACHE_CONTROL, "no-store")],
                "Service unavailable",
            )
                .into_response(),
        }
    }
}

/// The realm and user of a bearer token with account access.
struct Account {
    realm_id: String,
    user_id: String,
    session_id: String,
}

/// The account role a request needs.
#[derive(Clone, Copy)]
enum Need {
    /// Read the profile, credentials or sessions.
    View,
    /// Change the profile or end sessions.
    Manage,
    /// List the user's groups.
    Groups,
}

async fn authorize(
    state: &OidcState,
    realm: &str,
    headers: &HeaderMap,
    need: Need,
) -> Result<Account, AccountError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(AccountError::Unauthorized)?;
    let claims = verified_access(state, realm, token)
        .await
        .map_err(|()| AccountError::Unavailable)?
        .ok_or(AccountError::Unauthorized)?;
    let realm_id = state
        .storage
        .realm_id_by_name(realm)
        .await?
        .ok_or(AccountError::Unauthorized)?;
    let session = match state
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
        AccessTokenStatus::Active(session) => session,
        _ => return Err(AccountError::Unauthorized),
    };
    let roles = state
        .storage
        .effective_roles(&realm_id, &session.user_id)
        .await?;
    let account_roles = roles
        .clients
        .get("account")
        .map(Vec::as_slice)
        .unwrap_or_default();
    let allowed = match need {
        Need::View => account_roles
            .iter()
            .any(|role| role == "view-profile" || role == "manage-account"),
        Need::Manage => account_roles.iter().any(|role| role == "manage-account"),
        Need::Groups => account_roles
            .iter()
            .any(|role| role == "manage-account" || role == "view-groups"),
    };
    if !allowed {
        return Err(AccountError::Forbidden);
    }
    Ok(Account {
        realm_id,
        user_id: session.user_id,
        session_id: session.session_id,
    })
}

fn json_response(value: Value) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json;charset=UTF-8")],
        value.to_string(),
    )
        .into_response()
}

/// Whether the user may change their username here: never when the email
/// is the username, else when the realm allows it.
fn username_writable(settings: &UserSettings) -> bool {
    !settings.registration_email_as_username && settings.edit_username_allowed
}

/// Whether the email is read-only here: when it is the username and
/// usernames may not change.
fn email_read_only(settings: &UserSettings) -> bool {
    settings.registration_email_as_username && !settings.edit_username_allowed
}

/// The default user profile: username, email, first and last name, with
/// the reference's validators and its user-metadata group, and the locale
/// first when the realm is internationalized.
fn profile_metadata(settings: &UserSettings) -> Value {
    let mut metadata = json!({
        "attributes": [
            {
                "name": "username",
                "displayName": "${username}",
                "required": !settings.registration_email_as_username,
                "readOnly": !username_writable(settings),
                "validators": {
                    "username-prohibited-characters": {
                        "ignore.empty.value": true
                    },
                    "multivalued": {
                        "max": "1"
                    },
                    "length": {
                        "max": 255,
                        "ignore.empty.value": true,
                        "min": 3
                    },
                    "up-username-not-idn-homograph": {
                        "ignore.empty.value": true
                    }
                },
                "multivalued": false
            },
            {
                "name": "email",
                "displayName": "${email}",
                "required": true,
                "readOnly": email_read_only(settings),
                "annotations": {},
                "validators": {
                    "multivalued": {
                        "max": "1"
                    },
                    "length": {
                        "max": 255,
                        "ignore.empty.value": true
                    },
                    "email": {
                        "ignore.empty.value": true
                    }
                },
                "multivalued": false
            },
            {
                "name": "firstName",
                "displayName": "${firstName}",
                "required": true,
                "readOnly": false,
                "validators": {
                    "person-name-prohibited-characters": {
                        "ignore.empty.value": true
                    },
                    "multivalued": {
                        "max": "1"
                    },
                    "length": {
                        "max": 255,
                        "ignore.empty.value": true
                    }
                },
                "multivalued": false
            },
            {
                "name": "lastName",
                "displayName": "${lastName}",
                "required": true,
                "readOnly": false,
                "validators": {
                    "person-name-prohibited-characters": {
                        "ignore.empty.value": true
                    },
                    "multivalued": {
                        "max": "1"
                    },
                    "length": {
                        "max": 255,
                        "ignore.empty.value": true
                    }
                },
                "multivalued": false
            }
        ],
        "groups": [
            {
                "name": "user-metadata",
                "displayHeader": "User metadata",
                "displayDescription": "Attributes, which refer to user metadata"
            }
        ]
    });
    if settings.internationalization_enabled
        && let Some(Value::Array(attributes)) = metadata.get_mut("attributes")
    {
        attributes.insert(
            0,
            json!({
                "name": "locale",
                "displayName": "locale",
                "required": false,
                "readOnly": false,
                "validators": {},
                "multivalued": false
            }),
        );
    }
    metadata
}

/// Reads `attributes.locale` from an update: `None` when the realm is not
/// internationalized, which keeps the stored locale, and `Some(None)` when
/// the update leaves it out, which removes it.
fn requested_locale<'a>(
    fields: &'a Map<String, Value>,
    settings: &UserSettings,
) -> Result<Option<Option<&'a str>>, AccountError> {
    if !settings.internationalization_enabled {
        return Ok(None);
    }
    let invalid = || AccountError::Field(StatusCode::BAD_REQUEST, "locale", "error-invalid-value");
    let value = match fields
        .get("attributes")
        .and_then(|attributes| attributes.get("locale"))
    {
        None | Some(Value::Null) => None,
        Some(Value::String(tag)) => Some(tag.as_str()),
        Some(Value::Array(tags)) => match tags.as_slice() {
            [] => None,
            [Value::String(tag)] => Some(tag.as_str()),
            _ => return Err(invalid()),
        },
        Some(_) => return Err(invalid()),
    };
    match value {
        Some(tag) if tag.len() > 255 => Err(invalid()),
        Some(tag) => Ok(Some(Some(tag).filter(|tag| !tag.is_empty()))),
        None => Ok(Some(None)),
    }
}

async fn read_profile(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let account = authorize(&state, &realm, &headers, Need::View).await?;
    let user = state
        .storage
        .user(&account.realm_id, &account.user_id)
        .await?
        .ok_or(AccountError::Unauthorized)?;
    let settings = state.storage.user_settings(&account.realm_id).await?;
    let mut profile = json!({
        "id": user.id,
        "username": user.username,
        "emailVerified": user.email_verified,
        "userProfileMetadata": profile_metadata(&settings),
    });
    for (field, value) in [
        ("firstName", &user.first_name),
        ("lastName", &user.last_name),
        ("email", &user.email),
    ] {
        if let Some(value) = value {
            profile[field] = json!(value);
        }
    }
    if settings.internationalization_enabled
        && let Some(locale) = &user.locale
    {
        profile["attributes"] = json!({ "locale": [locale] });
    }
    Ok(json_response(profile))
}

async fn update_profile(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AccountError> {
    let account = authorize(&state, &realm, &headers, Need::Manage).await?;
    let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(&body) else {
        return Err(AccountError::Field(
            StatusCode::BAD_REQUEST,
            "username",
            "error-invalid-value",
        ));
    };
    let text = |name: &str| match fields.get(name) {
        Some(Value::String(value)) if !value.trim().is_empty() && value.len() <= 255 => {
            Some(value.trim().to_owned())
        }
        _ => None,
    };
    let current = state
        .storage
        .user(&account.realm_id, &account.user_id)
        .await?
        .ok_or(AccountError::Unauthorized)?;
    let settings = state.storage.user_settings(&account.realm_id).await?;
    let locale = requested_locale(&fields, &settings)?;
    // A read-only email keeps its stored value, whatever was sent.
    let email = if email_read_only(&settings) {
        current.email.clone()
    } else {
        text("email")
    };
    let requested_username = text("username");
    let mut username_errors = Vec::new();
    let (checked_username, saved_username) = if settings.registration_email_as_username {
        let email = email.clone().unwrap_or_default();
        (email.clone(), email)
    } else if username_writable(&settings) {
        let Some(username) = requested_username else {
            return Err(AccountError::Field(
                StatusCode::BAD_REQUEST,
                "username",
                "missingUsernameMessage",
            ));
        };
        (username.clone(), username)
    } else {
        if requested_username
            .as_ref()
            .is_some_and(|username| username.to_lowercase() != current.username)
        {
            username_errors.push(("username", "error-user-attribute-read-only"));
            username_errors.push(("username", "readOnlyUsernameMessage"));
        }
        (
            requested_username.unwrap_or_else(|| current.username.clone()),
            current.username.clone(),
        )
    };
    let profile = Profile {
        first_name: text("firstName"),
        last_name: text("lastName"),
        email,
    };
    if username_errors.is_empty()
        && profile
            .email
            .as_deref()
            .is_none_or(|email| !crate::mail::valid_email(email))
    {
        return Err(AccountError::Field(
            StatusCode::BAD_REQUEST,
            "email",
            "error-invalid-email",
        ));
    }
    if username_errors.is_empty() && profile.first_name.is_none() {
        return Err(AccountError::Field(
            StatusCode::BAD_REQUEST,
            "firstName",
            "error-user-attribute-required",
        ));
    }
    if username_errors.is_empty() && profile.last_name.is_none() {
        return Err(AccountError::Field(
            StatusCode::BAD_REQUEST,
            "lastName",
            "error-user-attribute-required",
        ));
    }
    let change = AccountChange {
        checked_username: &checked_username,
        saved_username: &saved_username,
        profile,
        locale,
        email_as_username: settings.registration_email_as_username,
    };
    let conflicts = state
        .storage
        .update_account(
            &account.realm_id,
            &account.user_id,
            &change,
            username_errors.is_empty(),
        )
        .await?;
    // The reference lists email errors before username errors.
    let mut errors = Vec::new();
    if conflicts.email_taken || conflicts.email_is_username {
        errors.push(("email", "emailExistsMessage"));
    }
    if conflicts.email_as_username {
        errors.push(("email", "usernameExistsMessage"));
    }
    errors.extend(username_errors);
    if conflicts.username_taken || conflicts.username_is_email {
        errors.push(("username", "usernameExistsMessage"));
    }
    match (conflicts.any(), errors.is_empty()) {
        (_, true) => Ok(StatusCode::NO_CONTENT),
        (true, false) => Err(AccountError::Fields(StatusCode::CONFLICT, errors)),
        (false, false) => Err(AccountError::Fields(StatusCode::BAD_REQUEST, errors)),
    }
}

async fn credentials(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let account = authorize(&state, &realm, &headers, Need::View).await?;
    let stored = state
        .storage
        .user_credentials(&account.realm_id, &account.user_id)
        .await?
        .unwrap_or_default();
    let metadata = |kind: &str| {
        stored
            .iter()
            .filter(|credential| credential.credential_type == kind)
            .map(|credential| {
                let mut entry = json!({ "id": credential.id, "type": credential.credential_type, "createdDate": credential.created });
                if let Some(label) = &credential.user_label {
                    entry["userLabel"] = json!(label);
                }
                json!({ "credential": entry })
            })
            .collect::<Vec<_>>()
    };
    Ok(json_response(json!([
        {
            "type": "password",
            "category": "basic-authentication",
            "displayName": "password-display-name",
            "helptext": "password-help-text",
            "iconCssClass": "kcAuthenticatorPasswordClass",
            "updateAction": "UPDATE_PASSWORD",
            "removeable": false,
            "userCredentialMetadatas": metadata("password"),
        },
        {
            "type": "otp",
            "category": "two-factor",
            "displayName": "otp-display-name",
            "helptext": "otp-help-text",
            "iconCssClass": "kcAuthenticatorOTPClass",
            "createAction": "CONFIGURE_TOTP",
            "removeable": true,
            "userCredentialMetadatas": metadata("otp"),
        },
    ])))
}

/// The user's sessions as the account API lists them.
async fn session_list(state: &OidcState, account: &Account) -> Result<Vec<Value>, AccountError> {
    let sessions = state
        .storage
        .account_sessions(&account.realm_id, &account.user_id)
        .await?;
    Ok(sessions
        .into_iter()
        .map(|session| {
            json!({
                "id": session.id,
                "started": session.started,
                "lastAccess": session.started,
                "expires": session.expires,
                // Addresses and user agents are not recorded.
                "ipAddress": null,
                "browser": null,
                "current": session.id == account.session_id,
                "clients": session.clients.iter().map(|client| json!({ "clientId": client })).collect::<Vec<_>>(),
            })
        })
        .collect())
}

async fn sessions(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let account = authorize(&state, &realm, &headers, Need::View).await?;
    Ok(json_response(Value::Array(
        session_list(&state, &account).await?,
    )))
}

/// The sessions grouped by device. User agents are not recorded, so every
/// session belongs to one unknown device.
async fn devices(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let account = authorize(&state, &realm, &headers, Need::View).await?;
    let sessions = session_list(&state, &account).await?;
    if sessions.is_empty() {
        return Ok(json_response(json!([])));
    }
    let last_access = sessions
        .iter()
        .filter_map(|session| session["lastAccess"].as_i64())
        .max();
    Ok(json_response(json!([{
        "os": "Other",
        "osVersion": "Unknown",
        "device": "Other",
        "lastAccess": last_access,
        "current": true,
        "mobile": false,
        "sessions": sessions,
    }])))
}

/// Ends every session of the user except the current one.
async fn end_other_sessions(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, AccountError> {
    let account = authorize(&state, &realm, &headers, Need::Manage).await?;
    state
        .storage
        .end_other_sessions(&account.realm_id, &account.session_id, true)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn applications(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let account = authorize(&state, &realm, &headers, Need::View).await?;
    let server = state.issuer_base.trim_end_matches('/');
    let listed = state
        .storage
        .account_applications(&account.realm_id, &account.user_id, &account.session_id)
        .await?
        .into_iter()
        .map(|app| {
            let mut fields = json!({
                "clientId": app.client_identifier,
                "userConsentRequired": app.consent_required,
                "inUse": app.in_use,
                "offlineAccess": app.offline,
            });
            if let Some(name) = &app.name {
                fields["clientName"] = json!(name);
            }
            if let Some(description) = &app.description {
                fields["description"] = json!(description);
            }
            if let Some(root_url) = &app.root_url {
                fields["rootUrl"] = json!(root_url);
            }
            if let Some(base_url) = &app.base_url {
                fields["baseUrl"] = json!(base_url);
                if let Some(effective) = resolve_redirect(base_url, app.root_url.as_deref(), server)
                {
                    fields["effectiveUrl"] = json!(effective);
                }
            }
            fields
        })
        .collect();
    Ok(json_response(Value::Array(listed)))
}

/// Removes the user's grant to a client: its consent and offline tokens.
async fn revoke_application(
    State(state): State<OidcState>,
    Path((realm, client)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let account = authorize(&state, &realm, &headers, Need::Manage).await?;
    if state
        .storage
        .clients(&account.realm_id, Some(&client))
        .await?
        .is_empty()
    {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(json!({ "errorMessage": format!("No client with clientId: {client} found.") })),
        )
            .into_response());
    }
    state
        .storage
        .revoke_consent(&account.realm_id, &account.user_id, &client)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn end_session(
    State(state): State<OidcState>,
    Path((realm, session)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AccountError> {
    let account = authorize(&state, &realm, &headers, Need::Manage).await?;
    let owned = state
        .storage
        .account_sessions(&account.realm_id, &account.user_id)
        .await?
        .iter()
        .any(|listed| listed.id == session);
    if !owned {
        return Err(AccountError::NotFound);
    }
    state
        .storage
        .logout_session(&account.realm_id, &session, &account.user_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The realm's supported locales, listed even while internationalization
/// is off, as in the reference.
async fn supported_locales(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let account = authorize(&state, &realm, &headers, Need::View).await?;
    let settings = state.storage.user_settings(&account.realm_id).await?;
    Ok(json_response(json!(settings.supported_locales)))
}

/// Realms here have no identity providers, so there is nothing to link.
async fn linked_accounts(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    authorize(&state, &realm, &headers, Need::View).await?;
    Ok(json_response(json!([])))
}

/// The groups the user is a direct member of, in brief form.
async fn groups(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let account = authorize(&state, &realm, &headers, Need::Groups).await?;
    let groups = state
        .storage
        .user_groups(&account.realm_id, &account.user_id)
        .await?
        .ok_or(AccountError::Unauthorized)?
        .into_iter()
        .map(|group| {
            let mut fields = json!({
                "id": group.id,
                "name": group.name,
                "path": group.path,
                "subGroups": [],
            });
            if let Some(parent) = group.parent_id {
                fields["parentId"] = json!(parent);
            }
            fields
        })
        .collect();
    Ok(json_response(Value::Array(groups)))
}
