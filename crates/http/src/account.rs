//! Keycloak's account REST API: a user's own profile, credentials and
//! sessions, authorized by their realm access token.
//!
//! Follows `tests/reference/account-api-observations.json`. Keycloak checks
//! the account client roles in the token; users receive those through the
//! realm's default role, so access here requires that role directly.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use rs_keycloak_storage_postgres::{AccessTokenStatus, Profile, StorageError};
use serde_json::{Value, json};

use crate::oidc::{OidcState, digest, verified_access};

/// Account routes, mounted with the public routes below the issuer path.
pub(crate) fn routes() -> Router<OidcState> {
    Router::new()
        .route(
            "/realms/{realm}/account",
            get(read_profile).post(update_profile),
        )
        .route("/realms/{realm}/account/credentials", get(credentials))
        .route("/realms/{realm}/account/sessions", get(sessions))
        .route(
            "/realms/{realm}/account/sessions/{session}",
            delete(end_session),
        )
}

/// Account API failures with the reference body shapes.
enum AccountError {
    Unauthorized,
    Forbidden,
    NotFound,
    /// A profile field failed validation.
    Field(StatusCode, &'static str, &'static str),
    Unavailable,
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
                let detail = json!({ "field": field, "errorMessage": message, "params": [field] });
                (
                    status,
                    Json(json!({ "field": field, "errorMessage": message, "params": [field], "errors": [detail] })),
                )
                    .into_response()
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

async fn authorize(
    state: &OidcState,
    realm: &str,
    headers: &HeaderMap,
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
    if !state
        .storage
        .account_access(&realm_id, &session.user_id)
        .await?
    {
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
        [(header::CONTENT_TYPE, "application/json")],
        value.to_string(),
    )
        .into_response()
}

/// The fixed default user profile: username, email, first and last name.
fn profile_metadata() -> Value {
    let attribute = |name: &str, display: &str, read_only: bool| json!({ "name": name, "displayName": display, "required": true, "readOnly": read_only, "multivalued": false });
    json!({
        "attributes": [
            attribute("username", "${username}", true),
            attribute("email", "${email}", false),
            attribute("firstName", "${firstName}", false),
            attribute("lastName", "${lastName}", false),
        ],
        "groups": [],
    })
}

async fn read_profile(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let account = authorize(&state, &realm, &headers).await?;
    let user = state
        .storage
        .user(&account.realm_id, &account.user_id)
        .await?
        .ok_or(AccountError::Unauthorized)?;
    let mut profile = json!({
        "id": user.id,
        "username": user.username,
        "emailVerified": user.email_verified,
        "userProfileMetadata": profile_metadata(),
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
    Ok(json_response(profile))
}

async fn update_profile(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AccountError> {
    let account = authorize(&state, &realm, &headers).await?;
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
    if text("username").is_some_and(|username| username.to_lowercase() != current.username) {
        return Err(AccountError::Field(
            StatusCode::BAD_REQUEST,
            "username",
            "error-user-attribute-read-only",
        ));
    }
    let profile = Profile {
        first_name: text("firstName"),
        last_name: text("lastName"),
        email: text("email"),
    };
    if profile
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
    if profile.first_name.is_none() {
        return Err(AccountError::Field(
            StatusCode::BAD_REQUEST,
            "firstName",
            "error-user-attribute-required",
        ));
    }
    if profile.last_name.is_none() {
        return Err(AccountError::Field(
            StatusCode::BAD_REQUEST,
            "lastName",
            "error-user-attribute-required",
        ));
    }
    if state
        .storage
        .update_account_profile(&account.realm_id, &account.user_id, &profile)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AccountError::Field(
            StatusCode::CONFLICT,
            "email",
            "emailExistsMessage",
        ))
    }
}

async fn credentials(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let account = authorize(&state, &realm, &headers).await?;
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

async fn sessions(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let account = authorize(&state, &realm, &headers).await?;
    let sessions = state
        .storage
        .account_sessions(&account.realm_id, &account.user_id)
        .await?;
    let listed = sessions
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
        .collect();
    Ok(json_response(Value::Array(listed)))
}

async fn end_session(
    State(state): State<OidcState>,
    Path((realm, session)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AccountError> {
    let account = authorize(&state, &realm, &headers).await?;
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
