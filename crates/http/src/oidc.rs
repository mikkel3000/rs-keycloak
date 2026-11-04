//! OIDC authorization-code request handling.

mod authorization_response;
mod cors;
mod introspection;
mod revocation;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::client_auth::{self, ClientAuthResult, ClientAuthenticator};
use axum::extract::rejection::FormRejection;
use axum::extract::{DefaultBodyLimit, Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rs_keycloak_authentication::{LoginResult, LoginService, PasswordWorkError};
use rs_keycloak_crypto::signing::{IdTokenClaims, SigningKey, TokenClaims, VerifiedToken};
use rs_keycloak_protocols::pkce::{self, Challenge};
use rs_keycloak_storage_postgres::{AccessTokenStatus, Storage};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Shared state for a single configured issuer.
#[derive(Clone)]
pub struct OidcState {
    storage: Arc<Storage>,
    login: Arc<LoginService>,
    client_auth: Arc<ClientAuthenticator>,
    signer: Arc<SigningKey>,
    signing_slots: Arc<Semaphore>,
    issuer_base: String,
    path_prefix: String,
}

impl OidcState {
    /// Creates state after storage, issuer, and persistent key validation.
    pub async fn new(
        storage: Arc<Storage>,
        signer: SigningKey,
        issuer_base: String,
    ) -> Result<Self, PasswordWorkError> {
        let path_prefix = issuer_path_prefix(&issuer_base).ok_or(PasswordWorkError)?;
        let login = LoginService::new(Arc::clone(&storage)).await?;
        let client_auth = ClientAuthenticator::new(Arc::clone(&storage)).await?;
        Ok(Self {
            storage,
            login: Arc::new(login),
            client_auth: Arc::new(client_auth),
            signer: Arc::new(signer),
            signing_slots: Arc::new(Semaphore::new(2)),
            issuer_base,
            path_prefix,
        })
    }
}

/// Extracts a literal issuer path safe for routing and cookie scoping.
/// Reserved routing and cookie delimiters must be percent-encoded in the URL.
pub fn issuer_path_prefix(issuer: &str) -> Option<String> {
    let issuer = Url::parse(issuer).ok()?;
    let prefix = issuer.path().trim_end_matches('/');
    if prefix.contains(['{', '}', ';'])
        || prefix
            .split('/')
            .any(|segment| segment.starts_with([':', '*']))
    {
        return None;
    }
    Some(prefix.to_owned())
}

/// Builds the public OIDC router with bounded request bodies.
pub fn router(state: OidcState) -> Router {
    let prefix = state.path_prefix.clone();
    let routes = Router::new()
        .route(
            "/realms/{realm}/protocol/openid-connect/auth",
            get(authorize),
        )
        .route(
            "/realms/{realm}/login-actions/authenticate/{request_id}",
            post(authenticate),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/token",
            post(token)
                .options(|| async { StatusCode::NO_CONTENT })
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    cors::handle,
                )),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/token/introspect",
            post(introspection::handle)
                .options(|| async { StatusCode::NO_CONTENT })
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    cors::handle,
                )),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/revoke",
            post(revocation::handle)
                .options(|| async { StatusCode::NO_CONTENT })
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    cors::handle,
                )),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/certs",
            get(certs)
                .options(|| async { StatusCode::OK })
                .layer(axum::middleware::from_fn(cors::metadata)),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/userinfo",
            get(userinfo)
                .post(userinfo)
                .options(|| async { StatusCode::NO_CONTENT })
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    cors::handle,
                )),
        )
        .route(
            "/realms/{realm}/.well-known/openid-configuration",
            get(discovery)
                .options(|| async { StatusCode::OK })
                .layer(axum::middleware::from_fn(cors::metadata)),
        )
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(state);
    if prefix.is_empty() {
        routes
    } else {
        Router::new().nest(&prefix, routes)
    }
}

#[derive(Deserialize)]
struct AuthorizationQuery {
    response_mode: Option<String>,
    client_id: String,
    redirect_uri: String,
    response_type: String,
    scope: String,
    code_challenge: String,
    code_challenge_method: String,
    state: Option<String>,
    nonce: Option<String>,
}

fn random_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
fn valid_realm(realm: &str) -> bool {
    !realm.is_empty()
        && realm.len() <= 255
        && realm
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn failure() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CACHE_CONTROL, "no-store")],
        "Invalid request",
    )
        .into_response()
}
fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CACHE_CONTROL, "no-store")],
        "Service unavailable",
    )
        .into_response()
}

async fn authorize(
    State(s): State<OidcState>,
    Path(realm): Path<String>,
    Query(q): Query<AuthorizationQuery>,
) -> Response {
    if !valid_realm(&realm)
        || q.response_type != "code"
        || q.code_challenge_method != "S256"
        || q.scope != "openid"
        || q.client_id.len() > 255
        || q.redirect_uri.len() > 2048
    {
        return failure();
    }
    let response_mode = q
        .response_mode
        .as_deref()
        .filter(|mode| !mode.is_empty())
        .unwrap_or("query");
    if !matches!(response_mode, "query" | "fragment" | "form_post") {
        return failure();
    }
    let Ok(challenge) = Challenge::parse(&q.code_challenge) else {
        return failure();
    };
    let realm_id = match s.storage.realm_id_by_name(&realm).await {
        Ok(Some(id)) => id,
        Ok(None) => return failure(),
        Err(_) => return unavailable(),
    };
    let csrf = random_token();
    let request_id = random_token();
    match s
        .storage
        .create_authorization_request(
            &request_id,
            &digest(&csrf),
            &realm_id,
            &q.client_id,
            &q.redirect_uri,
            challenge.digest(),
            q.state.as_deref(),
            &q.scope,
            q.nonce.as_deref(),
            300,
            response_mode,
        )
        .await
    {
        Ok(true) => (),
        Ok(false) => return failure(),
        Err(_) => return unavailable(),
    }
    let path_prefix = s.path_prefix.replace('&', "&amp;");
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign in</title></head><body><h1>Sign in</h1><form method=\"post\" action=\"{path_prefix}/realms/{realm}/login-actions/authenticate/{request_id}\"><label>Username <input name=\"username\" autocomplete=\"username\" required></label><label>Password <input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label><button>Sign in</button></form></body></html>"
    );
    let mut response = Html(html).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; form-action 'self'; frame-ancestors 'none'"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    let path_prefix = &s.path_prefix;
    let cookie = format!(
        "rs_auth={csrf}; Path={path_prefix}/realms/{realm}/login-actions/; Max-Age=300; Secure; HttpOnly; SameSite=Strict"
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    } else {
        return unavailable();
    }
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginForm {
    username: String,
    password: String,
}
fn csrf(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("rs_auth="))
}

async fn authenticate(
    State(s): State<OidcState>,
    Path((realm, request_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    if !valid_realm(&realm)
        || request_id.len() != 64
        || form.username.len() > 255
        || form.password.len() > 1024
    {
        return failure();
    }
    let Some(csrf) = csrf(&headers) else {
        return failure();
    };
    if csrf.len() != 64 {
        return failure();
    }
    let csrf_hash = digest(csrf);
    let (realm_id, client_id) = match s
        .storage
        .authorization_request_client(&request_id, &csrf_hash)
        .await
    {
        Ok(Some(binding)) => binding,
        Ok(None) => return failure(),
        Err(_) => return unavailable(),
    };
    match s.storage.realm_id_by_name(&realm).await {
        Ok(Some(id)) if id == realm_id => (),
        Ok(_) => return failure(),
        Err(_) => return unavailable(),
    }
    let password = Zeroizing::new(form.password.into_bytes());
    let result = s
        .login
        .authenticate(
            &realm_id,
            &client_id,
            &form.username.to_lowercase(),
            password,
        )
        .await;
    let session_id = match result {
        Ok(LoginResult::Authenticated { session_id }) => session_id,
        Ok(LoginResult::Denied) => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::CACHE_CONTROL, "no-store")],
                "Invalid credentials",
            )
                .into_response();
        }
        Err(_) => return unavailable(),
    };
    let code = random_token();
    let redirect = match s
        .storage
        .issue_authorization_code(&request_id, &csrf_hash, &session_id, &digest(&code), 60)
        .await
    {
        Ok(Some(redirect)) => redirect,
        Ok(None) => return failure(),
        Err(_) => return unavailable(),
    };
    let issuer = format!("{}/realms/{realm}", s.issuer_base.trim_end_matches('/'));
    let mut response = match authorization_response::build(redirect, &code, &issuer) {
        Ok(response) => response,
        Err(_) => return unavailable(),
    };
    let path_prefix = &s.path_prefix;
    let clear_cookie = format!(
        "rs_auth=; Path={path_prefix}/realms/{realm}/login-actions/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
    );
    if let Ok(value) = HeaderValue::from_str(&clear_cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

enum TokenForm {
    Code {
        code: String,
        redirect_uri: String,
        code_verifier: String,
    },
    Refresh {
        refresh_token: String,
        scope: Option<String>,
    },
}

fn token_error(error: &'static str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({"error":error})),
    )
        .into_response()
}

fn invalid_client(basic: bool) -> Response {
    if basic {
        (
            StatusCode::UNAUTHORIZED,
            [
                (header::WWW_AUTHENTICATE, "Basic realm=\"token\""),
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            Json(json!({"error":"invalid_client", "error_description":"Invalid client or Invalid client credentials"})),
        )
            .into_response()
    } else {
        token_error("invalid_client")
    }
}

fn unknown_client() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({"error":"invalid_client", "error_description":"Invalid client or Invalid client credentials"})),
    )
        .into_response()
}

fn unauthorized_client() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({"error":"unauthorized_client", "error_description":"Invalid client or Invalid client credentials"})),
    )
        .into_response()
}

fn invalid_grant() -> Response {
    token_error("invalid_grant")
}

struct ParsedTokenForm {
    grant: TokenForm,
    client_id: Option<String>,
    client_secret: Option<Zeroizing<String>>,
}

// Keep duplicate detection before dropping empty values or unknown extensions.
// RFC 6749 section 3.2 requires ignoring unknown and empty parameters.
fn token_form(pairs: Vec<(String, String)>) -> Result<ParsedTokenForm, &'static str> {
    let mut fields = BTreeMap::new();
    for (name, value) in pairs {
        if fields.insert(name, value).is_some() {
            return Err("invalid_request");
        }
    }
    fields.retain(|_, value| !value.is_empty());
    let client_id = fields.remove("client_id");
    let client_secret = fields.remove("client_secret").map(Zeroizing::new);
    let mut required = |name| fields.remove(name).ok_or("invalid_request");
    let grant = match required("grant_type")?.as_str() {
        "authorization_code" => Ok(TokenForm::Code {
            code: required("code")?,
            redirect_uri: required("redirect_uri")?,
            code_verifier: required("code_verifier")?,
        }),
        "refresh_token" => Ok(TokenForm::Refresh {
            refresh_token: required("refresh_token")?,
            scope: fields.remove("scope"),
        }),
        _ => Err("unsupported_grant_type"),
    }?;
    Ok(ParsedTokenForm {
        grant,
        client_id,
        client_secret,
    })
}

async fn token(
    State(s): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    form: Result<Form<Vec<(String, String)>>, FormRejection>,
) -> Response {
    let pairs = match form {
        Ok(Form(pairs)) => pairs,
        Err(_) => return token_error("invalid_request"),
    };
    let ParsedTokenForm {
        grant: q,
        client_id,
        client_secret,
    } = match token_form(pairs) {
        Ok(q) => q,
        Err(error) => return token_error(error),
    };
    if !valid_realm(&realm) {
        return token_error("invalid_request");
    }
    let realm_id = match s.storage.realm_id_by_name(&realm).await {
        Ok(Some(id)) => id,
        Ok(None) => return failure(),
        Err(_) => return unavailable(),
    };
    let credentials = match client_auth::parse(&headers, client_id, client_secret) {
        Ok(credentials) => credentials,
        Err(_) => return invalid_client(headers.contains_key(header::AUTHORIZATION)),
    };
    let client = match s.client_auth.authenticate(&realm_id, credentials).await {
        Ok(ClientAuthResult::Authenticated(client)) => client,
        Ok(ClientAuthResult::Unknown) => return unknown_client(),
        Ok(ClientAuthResult::Unauthorized) => return unauthorized_client(),
        Err(_) => return unavailable(),
    };
    let client_id = client.client_id;
    let client_revision = client.revision;
    let previous_jti = if let TokenForm::Refresh { refresh_token, .. } = &q {
        match verified_refresh(&s, &realm, refresh_token).await {
            Ok(Some(claims)) if claims.azp == client_id => Some(claims.jti),
            Ok(_) => return invalid_grant(),
            Err(_) => return unavailable(),
        }
    } else {
        None
    };
    let permit = match Arc::clone(&s.signing_slots).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return unavailable(),
    };
    let refresh_jti = Zeroizing::new(random_token());
    let (grant, refresh_expiry) = match q {
        TokenForm::Code {
            code,
            redirect_uri,
            code_verifier,
        } => {
            if code.len() != 64 || client_id.len() > 255 || redirect_uri.len() > 2048 {
                return token_error("invalid_request");
            }
            let Some(verifier) = pkce::verifier_digest(&code_verifier) else {
                return token_error("invalid_request");
            };
            let grant = match s
                .storage
                .redeem_authorization_code(
                    &digest(&code),
                    &realm_id,
                    &client_id,
                    &redirect_uri,
                    &verifier,
                    client_revision,
                )
                .await
            {
                Ok(Some(grant)) => grant,
                Ok(None) => return invalid_grant(),
                Err(_) => return unavailable(),
            };
            match s
                .storage
                .create_refresh_family(
                    &realm_id,
                    &client_id,
                    &grant.session_id,
                    &random_token(),
                    &digest(&refresh_jti),
                    &grant.scope,
                    1800,
                    client_revision,
                )
                .await
            {
                Ok(Some(expiry)) => (grant, expiry),
                Ok(None) => return invalid_grant(),
                Err(_) => return unavailable(),
            }
        }
        TokenForm::Refresh {
            refresh_token: previous,
            scope,
        } => {
            let previous = Zeroizing::new(previous);
            if previous.len() > 8192 || client_id.len() > 255 {
                return invalid_grant();
            }
            // Only openid is currently grantable; reject expansion before
            // consuming the supplied token so errors do not revoke a session.
            if scope.as_deref().is_some_and(|value| value != "openid") {
                return token_error("invalid_scope");
            }
            let Some(previous_jti) = previous_jti else {
                return invalid_grant();
            };
            let refreshed = match s
                .storage
                .rotate_refresh_token(
                    &realm_id,
                    &client_id,
                    &digest(&previous_jti),
                    &digest(&refresh_jti),
                    client_revision,
                )
                .await
            {
                Ok(Some(grant)) => grant,
                Ok(None) => return invalid_grant(),
                Err(_) => return unavailable(),
            };
            let expiry = refreshed.expires_at;
            (
                rs_keycloak_storage_postgres::CodeGrant {
                    realm_id: refreshed.session.realm_id,
                    user_id: refreshed.session.user_id,
                    session_id: refreshed.session.session_id,
                    client_id: refreshed.session.client_id,
                    client_identifier: refreshed.session.client_identifier,
                    scope: refreshed.scope,
                    nonce: None,
                    auth_time: refreshed.session.auth_time,
                },
                expiry,
            )
        }
    };
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => now.as_secs(),
        Err(_) => return unavailable(),
    };
    let Ok(refresh_expiry) = u64::try_from(refresh_expiry) else {
        return unavailable();
    };
    let refresh_expires_in = refresh_expiry.saturating_sub(now);
    let issuer = format!("{}/realms/{realm}", s.issuer_base.trim_end_matches('/'));
    let signer = Arc::clone(&s.signer);
    let tokens = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let jti = random_token();
        let claims = TokenClaims {
            iss: &issuer,
            sub: &grant.user_id,
            aud: &grant.client_identifier,
            iat: now,
            exp: now + 300,
            jti: &jti,
            azp: &grant.client_identifier,
            sid: &grant.session_id,
            scope: &grant.scope,
        };
        let id_claims = IdTokenClaims {
            iss: &issuer,
            sub: &grant.user_id,
            aud: &grant.client_identifier,
            iat: now,
            exp: now + 300,
            auth_time: grant.auth_time,
            nonce: grant.nonce.as_deref(),
        };
        let refresh_claims = TokenClaims {
            iss: &issuer,
            sub: &grant.user_id,
            aud: &issuer,
            iat: now,
            exp: refresh_expiry,
            jti: &refresh_jti,
            azp: &grant.client_identifier,
            sid: &grant.session_id,
            scope: &grant.scope,
        };
        Some((
            signer.sign(&claims).ok()?,
            signer.sign_id_token(&id_claims).ok()?,
            signer.sign_refresh_token(&refresh_claims).ok()?,
        ))
    })
    .await;
    let Ok(Some((access_token, id_token, refresh_token))) = tokens else {
        return unavailable();
    };
    ([(header::CACHE_CONTROL, "no-store"), (header::PRAGMA, "no-cache")], Json(json!({"access_token":access_token,"id_token":id_token,"token_type":"Bearer","expires_in":300,"scope":"openid","refresh_token":refresh_token,"refresh_expires_in":refresh_expires_in}))).into_response()
}

async fn certs(State(s): State<OidcState>, Path(realm): Path<String>) -> Response {
    if !valid_realm(&realm) {
        return failure();
    }
    match s.storage.realm_id_by_name(&realm).await {
        Ok(Some(_)) => Json(json!({"keys":[s.signer.public_jwk()]})).into_response(),
        Ok(None) => failure(),
        Err(_) => unavailable(),
    }
}
async fn discovery(State(s): State<OidcState>, Path(realm): Path<String>) -> Response {
    if !valid_realm(&realm) {
        return failure();
    }
    match s.storage.realm_id_by_name(&realm).await {
        Ok(Some(_)) => (),
        Ok(None) => return failure(),
        Err(_) => return unavailable(),
    }
    let issuer = format!("{}/realms/{realm}", s.issuer_base.trim_end_matches('/'));
    Json(json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/protocol/openid-connect/auth"),"token_endpoint":format!("{issuer}/protocol/openid-connect/token"),"jwks_uri":format!("{issuer}/protocol/openid-connect/certs"),"userinfo_endpoint":format!("{issuer}/protocol/openid-connect/userinfo"),"introspection_endpoint":format!("{issuer}/protocol/openid-connect/token/introspect"),"revocation_endpoint":format!("{issuer}/protocol/openid-connect/revoke"),"grant_types_supported":["authorization_code","refresh_token"],"response_types_supported":["code"],"response_modes_supported":["query","fragment","form_post"],"authorization_response_iss_parameter_supported":true,"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"],"scopes_supported":["openid"]})).into_response()
}

/// Builds a userinfo 401 with the reference Bearer challenge and empty body.
fn userinfo_challenge(realm: &str, description: Option<&str>) -> Response {
    let challenge = match description {
        Some(description) => format!(
            "Bearer realm=\"{realm}\", error=\"invalid_token\", error_description=\"{description}\""
        ),
        None => format!("Bearer realm=\"{realm}\""),
    };
    let Ok(challenge) = HeaderValue::from_str(&challenge) else {
        return failure();
    };
    (
        StatusCode::UNAUTHORIZED,
        [
            (header::WWW_AUTHENTICATE, challenge),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (header::PRAGMA, HeaderValue::from_static("no-cache")),
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain;charset=utf-8"),
            ),
        ],
    )
        .into_response()
}

async fn userinfo(
    State(s): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_realm(&realm) {
        return failure();
    }
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return userinfo_challenge(&realm, None);
    };
    let verification_failed = || userinfo_challenge(&realm, Some("Token verification failed"));
    let claims = match verified_access(&s, &realm, token).await {
        Ok(Some(claims)) => claims,
        Ok(None) => return verification_failed(),
        Err(()) => return unavailable(),
    };
    let realm_id = match s.storage.realm_id_by_name(&realm).await {
        Ok(Some(id)) => id,
        Ok(None) => return verification_failed(),
        Err(_) => return unavailable(),
    };
    match s
        .storage
        .active_access_token(
            &realm_id,
            &claims.azp,
            &claims.sid,
            &claims.sub,
            &digest(&claims.jti),
        )
        .await
    {
        Ok(AccessTokenStatus::Active(_)) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            Json(json!({"sub":claims.sub})),
        )
            .into_response(),
        Ok(AccessTokenStatus::Revoked) => verification_failed(),
        Ok(AccessTokenStatus::SessionNotFound) => {
            userinfo_challenge(&realm, Some("user_session_not_found"))
        }
        Err(_) => unavailable(),
    }
}

async fn verified_access(
    s: &OidcState,
    realm: &str,
    token: &str,
) -> Result<Option<VerifiedToken>, ()> {
    if token.len() > 8192 {
        return Ok(None);
    }
    let permit = Arc::clone(&s.signing_slots)
        .try_acquire_owned()
        .map_err(|_| ())?;
    let signer = Arc::clone(&s.signer);
    let token = Zeroizing::new(token.to_owned());
    let claims = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        signer.verify_access_token(&token)
    })
    .await
    .map_err(|_| ())?;
    let Ok(claims) = claims else { return Ok(None) };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs();
    let issuer = format!("{}/realms/{realm}", s.issuer_base.trim_end_matches('/'));
    if claims.iss != issuer
        || claims.iat > now
        || claims.exp <= now
        || claims.aud != claims.azp
        || claims.scope != "openid"
    {
        return Ok(None);
    }
    Ok(Some(claims))
}

async fn verified_refresh(
    s: &OidcState,
    realm: &str,
    token: &str,
) -> Result<Option<VerifiedToken>, ()> {
    if token.len() > 8192 {
        return Ok(None);
    }
    let permit = Arc::clone(&s.signing_slots)
        .try_acquire_owned()
        .map_err(|_| ())?;
    let signer = Arc::clone(&s.signer);
    let token = Zeroizing::new(token.to_owned());
    let claims = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        signer.verify_refresh_token(&token)
    })
    .await
    .map_err(|_| ())?;
    let Ok(claims) = claims else { return Ok(None) };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs();
    let issuer = format!("{}/realms/{realm}", s.issuer_base.trim_end_matches('/'));
    if claims.iss != issuer
        || claims.iat > now
        || claims.exp <= now
        || claims.aud != issuer
        || claims.scope != "openid"
    {
        return Ok(None);
    }
    Ok(Some(claims))
}
