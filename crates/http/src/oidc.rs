//! OIDC authorization-code request handling.

mod action_token;
mod authorization_response;
mod client_credentials;
mod consent;
mod cors;
mod iframes;
mod introspection;
mod login_locale;
mod login_steps;
mod logout;
mod notice;
mod registration;
mod reset_credentials;
mod revocation;
mod totp_qr;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::account_console::AccountConsole;
use crate::client_auth::{
    self, ClientAuthResult, ClientAuthenticator, InvalidClientAuthentication,
};
use crate::locale::PageLocale;
use crate::login_theme::escape;
use axum::extract::rejection::FormRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use login_locale::LocaleQuery;
use rs_keycloak_authentication::{LoginAttempt, LoginResult, LoginService, PasswordWorkError};
use rs_keycloak_crypto::secret_box::SecretKey;
use rs_keycloak_crypto::signing::{
    Audience, IdTokenClaims, RealmAccess, SigningKey, TokenClaims, UserClaims, VerifiedToken,
};
use rs_keycloak_protocols::client_urls::{redirect_matches, resolve_redirect};
use rs_keycloak_protocols::pkce::{self, Challenge};
use rs_keycloak_storage_postgres::{
    AccessTokenStatus, RefreshRotation, RoleNames, Storage, UserRecord, is_offline_scope,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384};
use tokio::sync::Semaphore;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Shared state for a single configured issuer.
#[derive(Clone)]
pub struct OidcState {
    pub(crate) storage: Arc<Storage>,
    login: Arc<LoginService>,
    client_auth: Arc<ClientAuthenticator>,
    pub(crate) signer: Arc<SigningKey>,
    signing_slots: Arc<Semaphore>,
    /// Bounds concurrent password hashing for admin credential changes.
    pub(crate) hash_slots: Arc<Semaphore>,
    /// Seals and opens recoverable client secrets, when configured.
    pub(crate) secret_key: Option<Arc<SecretKey>>,
    pub(crate) issuer_base: String,
    path_prefix: String,
    /// The pinned account console, when its directory is configured.
    pub(crate) account_console: Option<Arc<AccountConsole>>,
}

impl OidcState {
    /// Creates state after storage, issuer, and persistent key validation.
    /// `secret_key` seals client secrets the admin API must be able to return.
    pub async fn new(
        storage: Arc<Storage>,
        signer: SigningKey,
        issuer_base: String,
        secret_key: Option<SecretKey>,
    ) -> Result<Self, PasswordWorkError> {
        let path_prefix = issuer_path_prefix(&issuer_base).ok_or(PasswordWorkError)?;
        let login = LoginService::new(Arc::clone(&storage)).await?;
        let secret_key = secret_key.map(Arc::new);
        let client_auth =
            ClientAuthenticator::new(Arc::clone(&storage), secret_key.clone()).await?;
        Ok(Self {
            storage,
            login: Arc::new(login),
            client_auth: Arc::new(client_auth),
            signer: Arc::new(signer),
            signing_slots: Arc::new(Semaphore::new(2)),
            hash_slots: Arc::new(Semaphore::new(2)),
            secret_key,
            issuer_base,
            path_prefix,
            account_console: None,
        })
    }

    /// Serves the account console from an extracted directory.
    #[must_use]
    pub fn with_account_console(mut self, console: AccountConsole) -> Self {
        self.account_console = Some(Arc::new(console));
        self
    }

    /// The issuer's path below its origin, empty or starting with `/`.
    pub(crate) fn path_prefix(&self) -> &str {
        &self.path_prefix
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
            get(reshow).post(authenticate),
        )
        .route(
            "/realms/{realm}/login-actions/consent/{request_id}",
            post(consent::answer),
        )
        .route(
            "/realms/{realm}/login-actions/otp/{request_id}",
            post(login_steps::verify),
        )
        .route(
            "/realms/{realm}/login-actions/totp-setup/{request_id}",
            post(login_steps::configure),
        )
        .route(
            "/realms/{realm}/login-actions/update-password/{request_id}",
            post(login_steps::update_password),
        )
        .route(
            "/realms/{realm}/login-actions/update-profile/{request_id}",
            post(login_steps::update_profile),
        )
        .route(
            "/realms/{realm}/login-actions/required-action",
            get(login_steps::resend),
        )
        .route(
            "/realms/{realm}/login-actions/registration/{request_id}",
            get(registration::form).post(registration::submit),
        )
        .route(
            "/realms/{realm}/login-actions/reset-credentials",
            get(reset_credentials::form).post(reset_credentials::request),
        )
        .route(
            "/realms/{realm}/login-actions/action-token",
            get(action_token::show).post(action_token::submit),
        )
        .route(
            "/realms/{realm}/login-actions/detached-info",
            get(notice::detached_info),
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
            "/realms/{realm}/protocol/openid-connect/logout",
            get(logout::get).post(logout::post),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/logout/logout-confirm",
            get(logout::confirm_get).post(logout::confirm_post),
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
        .route("/realms/{realm}", get(realm_info))
        .route(
            "/realms/{realm}/.well-known/openid-configuration",
            get(discovery)
                .options(|| async { StatusCode::OK })
                .layer(axum::middleware::from_fn(cors::metadata)),
        )
        .merge(crate::admin::routes())
        .merge(crate::account::routes(state.clone()))
        .merge(crate::account_console::routes())
        .merge(iframes::routes())
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(axum::middleware::from_fn(crate::events::remember_address))
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
    prompt: Option<String>,
    max_age: Option<String>,
    ui_locales: Option<String>,
    login_hint: Option<String>,
}

/// Reads one cookie value from the request.
pub(crate) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .find_map(|part| part.strip_prefix(name)?.strip_prefix('='))
}

/// The SSO session cookies, set after login and cleared at logout.
/// `KEYCLOAK_SESSION` carries the unpadded base64url SHA-384 of the session
/// ID, which the login status iframe compares with `session_state`. As the
/// reference's AuthenticationManager, both live for the session's lifespan,
/// which `remembered` gives for a remembered session (its remember-me
/// lifespan, 0 or less for the normal one); otherwise the identity cookie
/// ends with the browser.
fn sso_cookies(
    path_prefix: &str,
    realm: &str,
    identity: Option<(&str, &str, Option<i32>)>,
) -> [String; 2] {
    let path = format!("{path_prefix}/realms/{realm}/");
    match identity {
        Some((token, session_id, remembered)) => {
            let lifespan = remembered
                .filter(|seconds| *seconds > 0)
                .unwrap_or(SSO_SESSION_MAX_LIFESPAN);
            let identity_age = match remembered {
                Some(_) => format!(" Max-Age={lifespan};"),
                None => String::new(),
            };
            [
                format!(
                    "KEYCLOAK_IDENTITY={token}; Version=1; Path={path};{identity_age} Secure; HttpOnly; SameSite=None"
                ),
                format!(
                    "KEYCLOAK_SESSION={}; Version=1; Path={path}; Max-Age={lifespan}; Secure; SameSite=None",
                    URL_SAFE_NO_PAD.encode(Sha384::digest(session_id.as_bytes()))
                ),
            ]
        }
        None => [
            // Clearing needs only the path, as the reference sends it.
            format!("KEYCLOAK_IDENTITY=; Path={path}; Max-Age=0"),
            format!("KEYCLOAK_SESSION=; Path={path}; Max-Age=0"),
        ],
    }
}

/// The reference re-authenticates only once `auth_time + max_age` is in the
/// past, comparing whole seconds.
fn reauthentication_required(auth_time: i64, max_age: i64, now: i64) -> bool {
    auth_time.saturating_add(max_age) < now
}

/// The reference's default `ssoSessionMaxLifespan` in seconds, the SSO
/// cookies' lifetime.
pub(crate) const SSO_SESSION_MAX_LIFESPAN: i32 = 36000;

/// The reference's default `ssoSessionIdleTimeout` in seconds, which stored
/// sessions and refresh tokens follow.
pub(crate) const SSO_SESSION_IDLE_TIMEOUT: i32 = 1800;

/// The realm's access and ID token lifetime in seconds, or `None` if it
/// cannot be read.
pub(crate) async fn token_lifespan(s: &OidcState, realm_id: &str) -> Option<u64> {
    let lifespan = s.storage.access_token_lifespan(realm_id).await.ok()?;
    u64::try_from(lifespan)
        .ok()
        .filter(|lifespan| *lifespan > 0)
}

pub(crate) fn random_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}
pub(crate) fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
pub(crate) fn valid_realm(realm: &str) -> bool {
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
pub(crate) fn unavailable() -> Response {
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
    headers: HeaderMap,
) -> Response {
    let prompts: Vec<&str> = q.prompt.as_deref().unwrap_or_default().split(' ').collect();
    let max_age = match q.max_age.as_deref().filter(|value| !value.is_empty()) {
        None => None,
        Some(value) => match value.parse::<i64>() {
            Ok(seconds) if seconds >= 0 => Some(seconds),
            _ => return failure(),
        },
    };
    if !valid_realm(&realm)
        || q.response_type != "code"
        || q.code_challenge_method != "S256"
        || q.scope.len() > 2048
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
    // The reference refuses these before a login exists, so its error
    // pages skip the client's ui_locales.
    let refuse = async |status, key, args: &[&str]| {
        let notice = notice::Notice::error(status, key).with_args(args);
        notice::error_page(&s, &realm, &realm_id, &headers, &notice).await
    };
    let rules = match s.storage.redirect_rules(&realm_id, &q.client_id).await {
        Ok(Some(rules)) => rules,
        Ok(None) => return refuse(StatusCode::BAD_REQUEST, "clientNotFoundMessage", &[]).await,
        Err(_) => return unavailable(),
    };
    if rules.bearer_only {
        return refuse(StatusCode::FORBIDDEN, "bearerOnlyMessage", &[]).await;
    }
    let server = s.issuer_base.trim_end_matches('/');
    let Some(registered) = rules.redirect_uris.iter().find(|registered| {
        resolve_redirect(registered, rules.root_url.as_deref(), server)
            .is_some_and(|resolved| redirect_matches(&resolved, &q.redirect_uri))
    }) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "invalidParameterMessage",
            &["redirect_uri"],
        )
        .await;
    };
    let Some(scope) = granted_login_scope(&q.scope) else {
        // The redirect URI is verified, so the error can go back to the client.
        let issuer = format!("{}/realms/{realm}", s.issuer_base.trim_end_matches('/'));
        let redirect = rs_keycloak_storage_postgres::AuthorizationRedirect {
            response_mode: response_mode.to_owned(),
            redirect_uri: q.redirect_uri.clone(),
            state: q.state.clone(),
        };
        return authorization_response::error(redirect, "invalid_scope", &issuer)
            .unwrap_or_else(|()| unavailable());
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
            registered,
            challenge.digest(),
            q.state.as_deref(),
            scope,
            q.nonce.as_deref(),
            300,
            response_mode,
            prompts.contains(&"consent"),
            // Overlong ui_locales count as absent rather than failing the login.
            q.ui_locales
                .as_deref()
                .filter(|tags| !tags.is_empty() && tags.len() <= 2048),
        )
        .await
    {
        Ok(true) => (),
        Ok(false) => return failure(),
        Err(_) => return unavailable(),
    }
    let redirect = rs_keycloak_storage_postgres::AuthorizationRedirect {
        response_mode: response_mode.to_owned(),
        redirect_uri: q.redirect_uri.clone(),
        state: q.state.clone(),
    };
    let issuer = format!("{}/realms/{realm}", s.issuer_base.trim_end_matches('/'));
    if !prompts.contains(&"login") {
        let session = match cookie(&headers, "KEYCLOAK_IDENTITY") {
            Some(token) => match s.storage.sso_session(&realm_id, &digest(token)).await {
                Ok(session) => session,
                Err(_) => return unavailable(),
            },
            None => None,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |now| now.as_secs() as i64);
        let session = session.filter(|session| {
            !max_age
                .is_some_and(|seconds| reauthentication_required(session.auth_time, seconds, now))
        });
        if let Some(session) = session {
            let request = RequestContext {
                realm: &realm,
                realm_id: &realm_id,
                request_id: &request_id,
                csrf: &csrf,
                issuer: &issuer,
                headers: &headers,
            };
            return match sso_response(&s, &request, &realm_id, &q.client_id, &session.session_id)
                .await
            {
                Ok(Some(answer)) => answer.into_response(),
                Ok(None) => failure(),
                Err(()) => unavailable(),
            };
        }
        if prompts.contains(&"none") {
            return authorization_response::error(redirect, "login_required", &issuer)
                .unwrap_or_else(|()| unavailable());
        }
    }
    let hint = q
        .login_hint
        .as_deref()
        .filter(|hint| !hint.is_empty() && hint.len() <= 255);
    login_page(
        &s,
        &realm,
        &request_id,
        &csrf,
        LoginNotice::None,
        &headers,
        hint,
    )
    .await
}

/// Renders the password form; after a failed attempt it shows the same form
/// again with an error, as the reference does.
/// Why a login-page submission was refused before its form was checked.
enum Rejection {
    /// The request, cookie or realm did not match a live login.
    Invalid,
    /// Storage could not answer.
    Unavailable,
}

impl Rejection {
    fn into_response(self) -> Response {
        match self {
            Self::Invalid => failure(),
            Self::Unavailable => unavailable(),
        }
    }
}

/// A message shown above the password form.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LoginNotice {
    None,
    /// The last attempt failed.
    Failed,
    /// A forgot-password request was accepted.
    EmailSent,
    /// The login was an email several users share.
    SharedEmail,
}

/// Renders the password form, with a forgot-password link when the realm
/// allows it.
/// The cookie that remembers the username, as the reference's
/// `KEYCLOAK_REMEMBER_ME`.
const REMEMBER_ME_COOKIE: &str = "KEYCLOAK_REMEMBER_ME";

/// The username of a remember-me cookie value: `username:` and the
/// form-encoded name, quoted as a version 1 cookie.
fn remembered_username(value: &str) -> Option<String> {
    let value = value.trim_matches('"');
    let (kind, encoded) = value.split_once(':')?;
    if kind != "username" {
        return None;
    }
    url::form_urlencoded::parse(format!("u={encoded}").as_bytes())
        .next()
        .map(|(_, name)| name.into_owned())
}

/// The remember-me cookie for a username, kept a year, or its removal.
fn remember_me_cookie(path_prefix: &str, realm: &str, username: Option<&str>) -> String {
    let path = format!("{path_prefix}/realms/{realm}/");
    match username {
        Some(username) => format!(
            "{REMEMBER_ME_COOKIE}=\"username:{}\"; Version=1; Path={path}; Max-Age=31536000; Secure; HttpOnly; SameSite=None",
            url::form_urlencoded::byte_serialize(username.as_bytes()).collect::<String>()
        ),
        None => format!("{REMEMBER_ME_COOKIE}=; Version=1; Path={path}; Max-Age=0"),
    }
}

async fn login_page(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    csrf: &str,
    notice: LoginNotice,
    headers: &HeaderMap,
    hint: Option<&str>,
) -> Response {
    let record = match s.storage.realm_by_name(realm).await {
        Ok(record) => record,
        Err(_) => return unavailable(),
    };
    let locale = match &record {
        Some(record) => {
            let locale = if notice == LoginNotice::EmailSent {
                login_locale::page_without_pick(s, &record.id, request_id, headers).await
            } else {
                login_locale::page(s, &record.id, request_id, headers).await
            };
            match locale {
                Ok(locale) => locale,
                Err(()) => return unavailable(),
            }
        }
        None => PageLocale::english(),
    };
    let reset_allowed = record
        .as_ref()
        .is_some_and(|record| record.reset_password_allowed);
    let remember_me = record
        .as_ref()
        .is_some_and(|record| record.login.remember_me);
    // As UsernamePasswordForm: login_hint fills the username, else a
    // remember-me cookie fills it and checks the box.
    let remembered = if remember_me && hint.is_none() {
        cookie(headers, REMEMBER_ME_COOKIE).and_then(remembered_username)
    } else {
        None
    };
    let username_value = hint.map(str::to_owned).or_else(|| remembered.clone());
    let prefix = escape(&s.path_prefix);
    let texts = &locale.messages;
    // A failed attempt marks the username field, as the reference does.
    let (message, error) = match notice {
        LoginNotice::None => (String::new(), String::new()),
        LoginNotice::Failed => (
            String::new(),
            field_error("username", &texts.html("invalidUserMessage", &[])),
        ),
        LoginNotice::EmailSent => (
            notice_message("status", &texts.html("emailSentMessage", &[])),
            String::new(),
        ),
        LoginNotice::SharedEmail => (
            notice_message("alert", &texts.html("usernameExistsMessage", &[])),
            String::new(),
        ),
    };
    let reset = if reset_allowed {
        format!(
            "<p><a href=\"{prefix}/realms/{realm}/login-actions/reset-credentials?request={request_id}\">{}</a></p>",
            texts.html("doForgotPassword", &[])
        )
    } else {
        String::new()
    };
    // As login.ftl, which shows the link with password login.
    let register = if record
        .as_ref()
        .is_some_and(|record| record.login.registration_allowed)
    {
        registration::link(&s.path_prefix, realm, request_id, &locale)
    } else {
        String::new()
    };
    let remember = if remember_me {
        format!(
            "<input type=\"checkbox\" id=\"rememberMe\" name=\"rememberMe\"{checked}><label for=\"rememberMe\">{label}</label>",
            checked = if remembered.is_some() { " checked" } else { "" },
            label = texts.html("rememberMe", &[]),
        )
    } else {
        String::new()
    };
    let body = format!(
        "{message}<form id=\"kc-form-login\" method=\"post\" action=\"{prefix}/realms/{realm}/login-actions/authenticate/{request_id}\"><label for=\"username\">{username}</label><input id=\"username\" name=\"username\" value=\"{value}\" autocomplete=\"username\" required>{error}<label for=\"password\">{password}</label><input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required>{remember}<button id=\"kc-login\" name=\"login\">{submit}</button></form>{reset}{register}",
        username = texts.html(locale.username_key(), &[]),
        value = escape(username_value.as_deref().unwrap_or_default()),
        password = texts.html("password", &[]),
        submit = texts.html("doLogIn", &[]),
    );
    let frame = Frame {
        heading: texts.text("loginAccountTitle", &[]),
        switch: reshow_url(&s.path_prefix, realm, request_id),
    };
    step_page(&s.path_prefix, realm, csrf, &locale, &frame, &body)
}

/// Re-shows a live login's current page, after a language link's
/// `kc_locale` pick: the password form, or once the password is checked,
/// the session's next step, as the reference's login-actions URLs do.
async fn reshow(
    State(s): State<OidcState>,
    Path((realm, request_id)): Path<(String, String)>,
    Query(locale_query): Query<LocaleQuery>,
    headers: HeaderMap,
) -> Response {
    if !valid_realm(&realm) || request_id.len() != 64 {
        return failure();
    }
    let Some(csrf) = csrf(&headers).filter(|csrf| csrf.len() == 64) else {
        return failure();
    };
    let csrf_hash = digest(csrf);
    let realm_id = match s
        .storage
        .authorization_request_client(&request_id, &csrf_hash)
        .await
    {
        Ok(Some((realm_id, _))) => realm_id,
        Ok(None) => return failure(),
        Err(_) => return unavailable(),
    };
    match s.storage.realm_id_by_name(&realm).await {
        Ok(Some(id)) if id == realm_id => (),
        Ok(_) => return failure(),
        Err(_) => return unavailable(),
    }
    let picked = match login_locale::pick(&s, &realm, &realm_id, &request_id, &locale_query).await {
        Ok(picked) => picked,
        Err(()) => return unavailable(),
    };
    let response = match s.storage.pending_request(&request_id, &csrf_hash).await {
        Ok(Some(pending)) => {
            let held = login_steps::Held {
                realm_id,
                session_id: pending.session_id,
                csrf: csrf.to_owned(),
            };
            login_steps::continue_login(&s, &realm, &request_id, &held, &headers).await
        }
        Ok(None) => {
            login_page(
                &s,
                &realm,
                &request_id,
                csrf,
                LoginNotice::None,
                &headers,
                None,
            )
            .await
        }
        Err(_) => return unavailable(),
    };
    login_locale::with_cookie(response, picked)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginForm {
    username: String,
    password: String,
    #[serde(rename = "rememberMe")]
    remember_me: Option<String>,
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
    Query(locale_query): Query<LocaleQuery>,
    connection: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    // Brute-force detection records where a failure came from.
    let address = connection.map(|Extension(ConnectInfo(peer))| peer.ip().to_string());
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
    let picked = match login_locale::pick(&s, &realm, &realm_id, &request_id, &locale_query).await {
        Ok(picked) => picked,
        Err(()) => return unavailable(),
    };
    let password = Zeroizing::new(form.password.into_bytes());
    // As AuthenticatorUtils.processRememberMe; the realm setting is checked
    // when the session is made.
    let remember_me = form
        .remember_me
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("on"));
    let result = s
        .login
        .authenticate(
            &LoginAttempt {
                realm_id: &realm_id,
                client_id: &client_id,
                username_normalized: &form.username.to_lowercase(),
                remember_me,
                address: address.as_deref(),
            },
            password,
        )
        .await;
    // A refused form keeps the username, as the reference's LoginBean.
    let hint = Some(form.username.as_str());
    let response = match result {
        Ok(LoginResult::Authenticated { session_id }) => {
            let held = login_steps::Held {
                realm_id,
                session_id,
                csrf: csrf.to_owned(),
            };
            login_steps::continue_login(&s, &realm, &request_id, &held, &headers).await
        }
        Ok(LoginResult::Denied) => {
            if crate::events::login_error(&s, &realm_id, &request_id, &form.username)
                .await
                .is_err()
            {
                return unavailable();
            }
            login_page(
                &s,
                &realm,
                &request_id,
                csrf,
                LoginNotice::Failed,
                &headers,
                hint,
            )
            .await
        }
        Ok(LoginResult::SharedEmail) => {
            login_page(
                &s,
                &realm,
                &request_id,
                csrf,
                LoginNotice::SharedEmail,
                &headers,
                hint,
            )
            .await
        }
        Err(_) => return unavailable(),
    };
    login_locale::with_cookie(response, picked)
}

/// Finishes an authenticated login: sets the SSO cookies, then shows consent
/// or sends the code. Only call this once every login step has passed.
async fn complete_login(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    held: &login_steps::Held,
    headers: &HeaderMap,
) -> Response {
    let (realm_id, csrf, session_id) = (
        held.realm_id.as_str(),
        held.csrf.as_str(),
        held.session_id.as_str(),
    );
    let issuer = format!("{}/realms/{realm}", s.issuer_base.trim_end_matches('/'));
    let sso_token = random_token();
    let session = match s
        .storage
        .set_sso_token(realm_id, session_id, &digest(&sso_token))
        .await
    {
        Ok(Some(session)) => session,
        Ok(None) => return failure(),
        Err(_) => return unavailable(),
    };
    let request = RequestContext {
        realm,
        realm_id,
        request_id,
        csrf,
        issuer: &issuer,
        headers,
    };
    let (mut response, consent_pending) = match consent_or_code(s, &request, session_id).await {
        Ok(Some(Answer::Consent(response))) => (response, true),
        Ok(Some(Answer::Code(response))) => (response, false),
        Ok(None) => return failure(),
        Err(()) => return unavailable(),
    };
    let remembered = session
        .remember_me
        .then_some(session.max_lifespan_remember_me);
    let mut cookies = sso_cookies(
        &s.path_prefix,
        realm,
        Some((&sso_token, session_id, remembered)),
    )
    .to_vec();
    // As AuthenticationManager: a remembered session names its user in the
    // remember-me cookie, and any other login removes a sent one.
    if session.remember_me {
        cookies.push(remember_me_cookie(
            &s.path_prefix,
            realm,
            Some(&session.username),
        ));
    } else if cookie(headers, REMEMBER_ME_COOKIE).is_some() {
        cookies.push(remember_me_cookie(&s.path_prefix, realm, None));
    }
    for value in cookies {
        match HeaderValue::from_str(&value) {
            Ok(value) => {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
            Err(_) => return unavailable(),
        }
    }
    // The consent page keeps the CSRF cookie that binds its form.
    if !consent_pending {
        let path_prefix = &s.path_prefix;
        let clear_cookie = format!(
            "rs_auth=; Path={path_prefix}/realms/{realm}/login-actions/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
        );
        if let Ok(value) = HeaderValue::from_str(&clear_cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

/// Renders a page in a locale with the login pages' security headers and no
/// cookies.
fn page(status: StatusCode, locale: &PageLocale, title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html{}><head><meta charset=\"utf-8\"><title>{title}</title></head><body>{body}</body></html>",
        locale.attributes()
    );
    let mut response = (status, Html(html)).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; form-action 'self'; frame-ancestors 'none'"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// What frames a login page's form: its heading, and the URL that re-shows
/// the page once a locale tag is appended.
struct Frame {
    /// The heading as text.
    heading: String,
    /// Ends in `kc_locale=`.
    switch: String,
}

/// The URL that re-shows a live login's current page in a locale, once the
/// tag is appended.
fn reshow_url(path_prefix: &str, realm: &str, request_id: &str) -> String {
    format!("{path_prefix}/realms/{realm}/login-actions/authenticate/{request_id}?kc_locale=")
}

/// A field's error, which the reference shows below the field.
fn field_error(field: &str, html: &str) -> String {
    format!("<span id=\"input-error-{field}\" role=\"alert\">{html}</span>")
}

/// A message above the form; `role` is `alert` for warnings and errors,
/// `status` for news.
fn notice_message(role: &str, html: &str) -> String {
    format!("<p class=\"kc-feedback-text\" role=\"{role}\">{html}</p>")
}

/// The realm's locales as links that re-show the page in each, the current
/// one marked, as the reference's language choice lists them.
fn language_links(locale: &PageLocale, switch: &str) -> String {
    if locale.languages.is_empty() {
        return String::new();
    }
    let links: Vec<String> = locale
        .languages
        .iter()
        .map(|(tag, label)| {
            let current = if *tag == locale.lang {
                " aria-current=\"true\""
            } else {
                ""
            };
            let encoded =
                percent_encoding::utf8_percent_encode(tag, percent_encoding::NON_ALPHANUMERIC);
            format!(
                "<a href=\"{}{encoded}\" hreflang=\"{}\"{current}>{}</a>",
                escape(switch),
                escape(tag),
                escape(label)
            )
        })
        .collect();
    format!(
        "<nav id=\"kc-locale\" aria-label=\"{}\">{}</nav>",
        locale.messages.html("languages", &[]),
        links.join(" ")
    )
}

/// Renders a login-theme page without cookies. As the reference's login
/// template does, the page is titled after the realm, names it above the
/// heading, and offers the realm's locales when it has several.
fn framed_page(realm: &str, locale: &PageLocale, frame: &Frame, body: &str) -> Response {
    framed_page_titled(realm, locale, None, frame, body)
}

/// As `framed_page`, titled `title` when given, as the logout
/// confirmation's template titles itself.
fn framed_page_titled(
    realm: &str,
    locale: &PageLocale,
    title: Option<&str>,
    frame: &Frame,
    body: &str,
) -> Response {
    let label = if locale.realm_label.is_empty() {
        realm
    } else {
        &locale.realm_label
    };
    let title = title.map_or_else(|| locale.messages.html("loginTitle", &[label]), escape);
    let body = format!(
        "<p id=\"kc-header\">{}</p><h1 id=\"kc-page-title\">{}</h1>{}{body}",
        escape(label),
        escape(&frame.heading),
        language_links(locale, &frame.switch)
    );
    page(StatusCode::OK, locale, &title, &body)
}

/// Renders a login-theme page that keeps the request's CSRF cookie so the
/// page's form stays bound to this browser.
fn step_page(
    path_prefix: &str,
    realm: &str,
    csrf: &str,
    locale: &PageLocale,
    frame: &Frame,
    body: &str,
) -> Response {
    let mut response = framed_page(realm, locale, frame, body);
    let headers = response.headers_mut();
    let cookie = format!(
        "rs_auth={csrf}; Path={path_prefix}/realms/{realm}/login-actions/; Max-Age=300; Secure; HttpOnly; SameSite=Strict"
    );
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            headers.append(header::SET_COOKIE, value);
            response
        }
        Err(_) => unavailable(),
    }
}

/// A validated authorization request bound to its CSRF cookie.
struct RequestContext<'a> {
    realm: &'a str,
    realm_id: &'a str,
    request_id: &'a str,
    csrf: &'a str,
    issuer: &'a str,
    /// The browser's headers, which help choose the consent page's locale.
    headers: &'a HeaderMap,
}

/// How an authenticated authorization request is answered.
enum Answer {
    /// The consent screen, which keeps the request's CSRF cookie.
    Consent(Response),
    /// The authorization response carrying a code.
    Code(Response),
}

impl Answer {
    fn into_response(self) -> Response {
        match self {
            Self::Consent(response) | Self::Code(response) => response,
        }
    }
}

/// Shows the consent screen if the client needs it, otherwise issues a code.
/// Returns `None` when the request is no longer valid.
async fn consent_or_code(
    s: &OidcState,
    request: &RequestContext<'_>,
    session_id: &str,
) -> Result<Option<Answer>, ()> {
    let csrf_hash = digest(request.csrf);
    if s.storage
        .consent_needed(request.request_id, &csrf_hash, session_id)
        .await
        .map_err(|_| ())?
    {
        let pending = s
            .storage
            .attach_pending_session(request.request_id, &csrf_hash, session_id)
            .await
            .map_err(|_| ())?;
        let Some(pending) = pending else {
            return Ok(None);
        };
        let locale =
            login_locale::page(s, request.realm_id, request.request_id, request.headers).await?;
        return Ok(Some(Answer::Consent(consent::page(
            &s.path_prefix,
            request.realm,
            request.request_id,
            &pending.client_identifier,
            request.csrf,
            &locale,
        ))));
    }
    crate::events::login(s, request.realm_id, request.request_id, session_id, false)
        .await
        .map_err(|_| ())?;
    let code = random_token();
    let redirect = s
        .storage
        .issue_authorization_code(
            request.request_id,
            &csrf_hash,
            session_id,
            &digest(&code),
            60,
        )
        .await
        .map_err(|_| ())?;
    match redirect {
        Some(redirect) => {
            authorization_response::build(redirect, &code, session_id, request.issuer)
                .map(|response| Some(Answer::Code(response)))
        }
        None => Ok(None),
    }
}

/// Answers an authorization request from an existing SSO session, after the
/// client joins the session.
async fn sso_response(
    s: &OidcState,
    request: &RequestContext<'_>,
    realm_id: &str,
    client_id: &str,
    session_id: &str,
) -> Result<Option<Answer>, ()> {
    let joined = s
        .storage
        .join_client_session(realm_id, session_id, client_id, &Uuid::new_v4().to_string())
        .await
        .map_err(|_| ())?;
    if !joined {
        return Ok(None);
    }
    consent_or_code(s, request, session_id).await
}

/// Grants that redeem or extend a stored user session.
enum SessionGrant {
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

/// A parsed token request grant.
enum TokenForm {
    Session(SessionGrant),
    ClientCredentials { scope: Option<String> },
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

fn invalid_grant_described(description: &'static str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({"error":"invalid_grant","error_description":description})),
    )
        .into_response()
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
        "authorization_code" => Ok(TokenForm::Session(SessionGrant::Code {
            code: required("code")?,
            redirect_uri: required("redirect_uri")?,
            code_verifier: required("code_verifier")?,
        })),
        "refresh_token" => Ok(TokenForm::Session(SessionGrant::Refresh {
            refresh_token: required("refresh_token")?,
            scope: fields.remove("scope"),
        })),
        "client_credentials" => Ok(TokenForm::ClientCredentials {
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
        Err(InvalidClientAuthentication::Missing) => return unknown_client(),
        Err(InvalidClientAuthentication::Malformed) => {
            return invalid_client(headers.contains_key(header::AUTHORIZATION));
        }
    };
    let client = match s.client_auth.authenticate(&realm_id, credentials).await {
        Ok(ClientAuthResult::Authenticated(client)) => client,
        Ok(ClientAuthResult::Unknown) => return unknown_client(),
        Ok(ClientAuthResult::Unauthorized) => return unauthorized_client(),
        Err(_) => return unavailable(),
    };
    if client.bearer_only {
        return client_auth::bearer_only_refused();
    }
    let q = match q {
        TokenForm::Session(grant) => grant,
        TokenForm::ClientCredentials { scope } => {
            return client_credentials::grant(&s, &realm, &realm_id, client, scope.as_deref())
                .await;
        }
    };
    let client_id = client.client_id;
    let client_revision = client.revision;
    let previous_jti = if let SessionGrant::Refresh { refresh_token, .. } = &q {
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
    let (grant, refresh_expiry, issued) = match q {
        SessionGrant::Code {
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
                Ok(Some(family)) => (grant, family.expires_at, Some(family.issued)),
                Ok(None) => return invalid_grant(),
                Err(_) => return unavailable(),
            }
        }
        SessionGrant::Refresh {
            refresh_token: previous,
            scope,
        } => {
            let previous = Zeroizing::new(previous);
            if previous.len() > 8192 || client_id.len() > 255 {
                return invalid_grant();
            }
            // Refuse unknown scopes before consuming the supplied token, so
            // errors do not revoke a session. The refreshed tokens keep the
            // family's granted scope, so a request cannot widen it.
            if scope
                .as_deref()
                .is_some_and(|value| granted_login_scope(value).is_none())
            {
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
                Ok(RefreshRotation::Rotated(grant)) => grant,
                Ok(RefreshRotation::SessionNotActive) => {
                    return invalid_grant_described("Session not active");
                }
                Ok(RefreshRotation::OfflineSessionNotFound) => {
                    return invalid_grant_described("Offline user session not found");
                }
                Ok(RefreshRotation::Invalid) => return invalid_grant(),
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
                refreshed.issued,
            )
        }
    };
    // Tokens are issued at the second their family's expiry was set from,
    // so a new or refreshed offline family's refresh_expires_in is its
    // whole lifetime.
    let now = match issued.and_then(|issued| u64::try_from(issued).ok()) {
        Some(issued) => issued,
        None => match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(now) => now.as_secs(),
            Err(_) => return unavailable(),
        },
    };
    let Ok(refresh_expiry) = u64::try_from(refresh_expiry) else {
        return unavailable();
    };
    let refresh_expires_in = refresh_expiry.saturating_sub(now);
    let Ok(roles) = s.storage.effective_roles(&realm_id, &grant.user_id).await else {
        return unavailable();
    };
    let Some(lifespan) = token_lifespan(&s, &realm_id).await else {
        return unavailable();
    };
    let user = match s.storage.user(&realm_id, &grant.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return invalid_grant(),
        Err(_) => return unavailable(),
    };
    let openid = has_openid_scope(&grant.scope);
    let offline = is_offline_scope(&grant.scope);
    if offline && !roles.realm.iter().any(|role| role == "offline_access") {
        // The reference's answer when the user lacks the offline_access role.
        return (
            StatusCode::BAD_REQUEST,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            Json(json!({"error":"not_allowed","error_description":"Offline tokens not allowed for the user or client"})),
        )
            .into_response();
    }
    let Ok(audiences) = s
        .storage
        .token_audiences(&realm_id, &grant.client_identifier)
        .await
    else {
        return unavailable();
    };
    let access_audience = Audience::new(
        &grant.client_identifier,
        audiences.access.iter().map(String::as_str),
    );
    let id_audience = Audience::new(
        &grant.client_identifier,
        audiences.id.iter().map(String::as_str),
    );
    let scope = grant.scope.clone();
    let issuer = format!("{}/realms/{realm}", s.issuer_base.trim_end_matches('/'));
    let signer = Arc::clone(&s.signer);
    let tokens = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let jti = random_token();
        let claims = TokenClaims {
            iss: &issuer,
            sub: &grant.user_id,
            aud: access_audience,
            iat: now,
            exp: now + lifespan,
            jti: &jti,
            azp: &grant.client_identifier,
            sid: Some(&grant.session_id),
            scope: &grant.scope,
            realm_access: Some(RealmAccess {
                roles: &roles.realm,
            }),
            resource_access: resource_access(&roles),
            user: user_claims(&user, &grant.scope),
        };
        let id_claims = IdTokenClaims {
            iss: &issuer,
            sub: &grant.user_id,
            aud: id_audience,
            iat: now,
            exp: now + lifespan,
            auth_time: Some(grant.auth_time),
            nonce: grant.nonce.as_deref(),
            sid: Some(&grant.session_id),
            user: user_claims(&user, &grant.scope),
        };
        let refresh_claims = TokenClaims {
            iss: &issuer,
            sub: &grant.user_id,
            aud: Audience::new(&issuer, []),
            iat: now,
            exp: refresh_expiry,
            jti: &refresh_jti,
            azp: &grant.client_identifier,
            sid: Some(&grant.session_id),
            scope: &grant.scope,
            realm_access: None,
            resource_access: None,
            user: UserClaims::default(),
        };
        // Only an `openid` grant gets an ID token, as in the reference.
        let id_token = if openid {
            Some(signer.sign_id_token(&id_claims).ok()?)
        } else {
            None
        };
        let refresh_token = if offline {
            signer.sign_offline_token(&refresh_claims).ok()?
        } else {
            signer.sign_refresh_token(&refresh_claims).ok()?
        };
        Some((signer.sign(&claims).ok()?, id_token, refresh_token))
    })
    .await;
    let Ok(Some((access_token, id_token, refresh_token))) = tokens else {
        return unavailable();
    };
    let mut body = json!({"access_token":access_token,"token_type":"Bearer","expires_in":lifespan,"scope":scope,"refresh_token":refresh_token,"refresh_expires_in":refresh_expires_in});
    if let Some(id_token) = id_token {
        body["id_token"] = json!(id_token);
    }
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response()
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
/// Serves the public realm document, `PublicRealmResource.getRealm` in the
/// reference. Disabled realms are served too, as the reference does.
async fn realm_info(
    State(s): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_realm(&realm) {
        return failure();
    }
    match s.storage.realm_by_name(&realm).await {
        Ok(Some(_)) => (),
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"Realm does not exist"})),
            )
                .into_response();
        }
        Err(_) => return unavailable(),
    }
    let issuer = format!("{}/realms/{realm}", s.issuer_base.trim_end_matches('/'));
    // Realm-wide not-before revocation is not stored, so it stays 0 as on a
    // realm where it was never pushed.
    let mut response = (
        [(header::CACHE_CONTROL, "no-cache")],
        Json(json!({
            "realm": realm,
            "public_key": s.signer.public_key_info(),
            "token-service": format!("{issuer}/protocol/openid-connect"),
            "account-service": format!("{issuer}/account"),
            "tokens-not-before": 0,
        })),
    )
        .into_response();
    // The reference allows every origin here, with credentials.
    if let Some(origin) = headers.get(header::ORIGIN) {
        let origin = origin.clone();
        let out = response.headers_mut();
        out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        out.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
    response
}

async fn discovery(State(s): State<OidcState>, Path(realm): Path<String>) -> Response {
    if !valid_realm(&realm) {
        return failure();
    }
    // The reference serves discovery for disabled realms too.
    match s.storage.realm_by_name(&realm).await {
        Ok(Some(_)) => (),
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"Realm does not exist"})),
            )
                .into_response();
        }
        Err(_) => return unavailable(),
    }
    let issuer = format!("{}/realms/{realm}", s.issuer_base.trim_end_matches('/'));
    let cache = [(
        header::CACHE_CONTROL,
        "no-cache, must-revalidate, no-transform, no-store",
    )];
    (cache, Json(json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/protocol/openid-connect/auth"),"token_endpoint":format!("{issuer}/protocol/openid-connect/token"),"jwks_uri":format!("{issuer}/protocol/openid-connect/certs"),"userinfo_endpoint":format!("{issuer}/protocol/openid-connect/userinfo"),"introspection_endpoint":format!("{issuer}/protocol/openid-connect/token/introspect"),"revocation_endpoint":format!("{issuer}/protocol/openid-connect/revoke"),"end_session_endpoint":format!("{issuer}/protocol/openid-connect/logout"),"grant_types_supported":["authorization_code","refresh_token","client_credentials"],"response_types_supported":["code"],"response_modes_supported":["query","fragment","form_post"],"authorization_response_iss_parameter_supported":true,"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"],"scopes_supported":["openid"]}))).into_response()
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

/// The `resource_access` claim for a user's client roles, or `None` when
/// the user has none, as the reference omits it then.
fn resource_access(roles: &RoleNames) -> Option<BTreeMap<&str, RealmAccess<'_>>> {
    (!roles.clients.is_empty()).then(|| {
        roles
            .clients
            .iter()
            .map(|(client, names)| (client.as_str(), RealmAccess { roles: names }))
            .collect()
    })
}

/// The scopes a login grants: `openid` and `offline_access` when requested,
/// plus the reference's default `email` and `profile` scopes, which every
/// client has. `None` when
/// the request names a scope no client has here.
fn granted_login_scope(requested: &str) -> Option<&'static str> {
    let mut openid = false;
    let mut offline = false;
    for value in requested.split(' ').filter(|value| !value.is_empty()) {
        match value {
            "openid" => openid = true,
            "offline_access" => offline = true,
            "email" | "profile" => (),
            _ => return None,
        }
    }
    Some(match (openid, offline) {
        (true, false) => "openid email profile",
        (true, true) => "openid email offline_access profile",
        (false, false) => "email profile",
        (false, true) => "email offline_access profile",
    })
}

/// The `profile` and `email` claims a user's token carries for its scopes.
pub(crate) fn user_claims<'a>(user: &'a UserRecord, scope: &str) -> UserClaims<'a> {
    let granted = |name: &str| scope.split(' ').any(|value| value == name);
    let mut claims = UserClaims::default();
    if granted("profile") {
        claims.preferred_username = Some(&user.username);
        claims.given_name = user.first_name.as_deref();
        claims.family_name = user.last_name.as_deref();
        let name = [user.first_name.as_deref(), user.last_name.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        claims.name = Some(name).filter(|name| !name.is_empty());
    }
    if granted("email") {
        claims.email = user.email.as_deref();
        claims.email_verified = Some(user.email_verified);
    }
    claims
}

/// Reports whether a space-separated scope string grants `openid`.
fn has_openid_scope(scope: &str) -> bool {
    scope.split(' ').any(|value| value == "openid")
}

/// Builds the reference 403 for userinfo tokens issued without `openid`.
fn userinfo_missing_openid(realm: &str) -> Response {
    let challenge = format!(
        "Bearer realm=\"{realm}\", error=\"insufficient_scope\", error_description=\"Missing openid scope\""
    );
    let Ok(challenge) = HeaderValue::from_str(&challenge) else {
        return failure();
    };
    (
        StatusCode::FORBIDDEN,
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
    if !has_openid_scope(&claims.scope) {
        return userinfo_missing_openid(&realm);
    }
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
            claims.sid.as_deref(),
            &claims.sub,
            &digest(&claims.jti),
        )
        .await
    {
        Ok(AccessTokenStatus::Active(_) | AccessTokenStatus::ServiceAccount(_)) => {
            let mut body = json!({"sub":claims.sub});
            // The profile and email scopes add their claims, as in the tokens.
            if claims
                .scope
                .split(' ')
                .any(|scope| matches!(scope, "profile" | "email"))
            {
                let user = match s.storage.user(&realm_id, &claims.sub).await {
                    Ok(Some(user)) => user,
                    Ok(None) => return verification_failed(),
                    Err(_) => return unavailable(),
                };
                let Ok(Value::Object(extra)) =
                    serde_json::to_value(user_claims(&user, &claims.scope))
                else {
                    return unavailable();
                };
                if let Some(fields) = body.as_object_mut() {
                    fields.extend(extra);
                }
            }
            (
                [
                    (header::CACHE_CONTROL, "no-store"),
                    (header::PRAGMA, "no-cache"),
                ],
                Json(body),
            )
                .into_response()
        }
        Ok(AccessTokenStatus::ClientNotFound) => {
            userinfo_challenge(&realm, Some("Client not found"))
        }
        Ok(AccessTokenStatus::Revoked) => verification_failed(),
        Ok(AccessTokenStatus::SessionNotFound) => {
            userinfo_challenge(&realm, Some("user_session_not_found"))
        }
        Err(_) => unavailable(),
    }
}

pub(crate) async fn verified_access(
    s: &OidcState,
    realm: &str,
    token: &str,
) -> Result<Option<VerifiedToken>, ()> {
    Ok(verified_access_any(s, token)
        .await?
        .filter(|(issuer, _)| issuer == realm)
        .map(|(_, claims)| claims))
}

/// Verifies a live access token from any realm; returns the issuing realm's
/// name with the claims. All realms share the signing key, so one
/// verification is enough to trust the issuer.
pub(crate) async fn verified_access_any(
    s: &OidcState,
    token: &str,
) -> Result<Option<(String, VerifiedToken)>, ()> {
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
    let prefix = format!("{}/realms/", s.issuer_base.trim_end_matches('/'));
    let Some(realm) = claims
        .iss
        .strip_prefix(&prefix)
        .filter(|realm| valid_realm(realm))
    else {
        return Ok(None);
    };
    // Like the reference, only expiry is checked against the clock: a token
    // issued a moment "in the future" by a clock step is still valid.
    // Access tokens name their own client first; audience mappers add the
    // others after it.
    if claims.exp <= now || claims.aud.first() != claims.azp {
        return Ok(None);
    }
    Ok(Some((realm.to_owned(), claims)))
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
        || claims.exp <= now
        || !claims.aud.is_only(&issuer)
        || granted_login_scope(&claims.scope).is_none()
    {
        return Ok(None);
    }
    Ok(Some(claims))
}

#[cfg(test)]
mod tests {
    use super::reauthentication_required;

    #[test]
    fn max_age_counts_whole_seconds_like_the_reference() {
        assert!(!reauthentication_required(100, 0, 100));
        assert!(reauthentication_required(100, 0, 101));
        assert!(!reauthentication_required(100, 60, 160));
        assert!(reauthentication_required(100, 60, 161));
        assert!(!reauthentication_required(i64::MAX, 1, 0));
    }
}
