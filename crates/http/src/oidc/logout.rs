//! OIDC logout: refresh-token POST logout and RP-initiated browser logout.
//!
//! Follows the recorded cases in `tests/reference/logout-observations.json`
//! and `tests/reference/login-info-page-observations.json`, and
//! `LogoutEndpoint` at the pinned revision: a browser logout the client
//! cannot vouch for asks for confirmation, then ends the session of the
//! ID token hint and of the SSO cookie, and shows the logged-out page or
//! redirects.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use rs_keycloak_crypto::signing::VerifiedIdToken;
use rs_keycloak_protocols::client_urls::{redirect_matches, resolve_redirect};
use rs_keycloak_storage_postgres::{LoginLocale, LogoutRequest, RefreshLogout, SsoSession};
use serde::Deserialize;
use serde_json::json;
use url::Url;
use zeroize::Zeroizing;

use crate::client_auth::{self, ClientAuthResult, InvalidClientAuthentication};
use crate::locale::{self, PageLocale};
use crate::login_theme::escape;

use super::login_locale::{self, LocaleQuery};
use super::notice::{self, Notice};
use super::{
    Frame, OidcState, cookie, digest, framed_page_titled, invalid_client, random_token,
    sso_cookies, unavailable, valid_realm, verified_refresh,
};

/// How long a logout waits for confirmation, the reference's default
/// user-action lifespan.
const CONFIRM_SECONDS: i32 = 300;

/// The cookie that binds a logout confirmation to this browser.
const CSRF_COOKIE: &str = "rs_logout";

fn page(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-cache")],
        Html(format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Logout</title></head><body><p>{message}</p></body></html>"
        )),
    )
        .into_response()
}

/// Logout errors, which the reference sends without cache headers.
fn error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({"error":error,"error_description":description})),
    )
        .into_response()
}

fn invalid_grant(description: &str) -> Response {
    error(StatusCode::BAD_REQUEST, "invalid_grant", description)
}

fn client_error(error_code: &str) -> Response {
    error(
        StatusCode::UNAUTHORIZED,
        error_code,
        "Invalid client or Invalid client credentials",
    )
}

/// Why a logout request's realm could not be used.
enum RealmError {
    Invalid,
    Missing,
    Unavailable,
}

impl IntoResponse for RealmError {
    fn into_response(self) -> Response {
        match self {
            Self::Invalid => page(StatusCode::BAD_REQUEST, "Invalid request."),
            Self::Missing => page(StatusCode::NOT_FOUND, "Realm does not exist."),
            Self::Unavailable => unavailable(),
        }
    }
}

async fn realm_id(state: &OidcState, realm: &str) -> Result<String, RealmError> {
    if !valid_realm(realm) {
        return Err(RealmError::Invalid);
    }
    state
        .storage
        .realm_id_by_name(realm)
        .await
        .map_err(|_| RealmError::Unavailable)?
        .ok_or(RealmError::Missing)
}

/// Handles `POST /logout`; without a refresh token it is a browser logout.
pub(super) async fn post(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    form: Result<Form<Vec<(String, String)>>, FormRejection>,
) -> Response {
    let Ok(Form(pairs)) = form else {
        return page(StatusCode::BAD_REQUEST, "Invalid request.");
    };
    let mut fields = BTreeMap::new();
    for (name, value) in pairs {
        if fields.insert(name, value).is_some() {
            return page(StatusCode::BAD_REQUEST, "Invalid request.");
        }
    }
    let Some(refresh_token) = fields.remove("refresh_token").map(Zeroizing::new) else {
        return browser(state, realm, fields, headers).await;
    };
    let realm_id = match realm_id(&state, &realm).await {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let credentials = match client_auth::parse(
        &headers,
        fields.remove("client_id"),
        fields.remove("client_secret").map(Zeroizing::new),
    ) {
        Ok(credentials) => credentials,
        Err(InvalidClientAuthentication::Missing) => return client_error("invalid_client"),
        Err(InvalidClientAuthentication::Malformed) => {
            return invalid_client(headers.contains_key(header::AUTHORIZATION));
        }
    };
    let client = match state.client_auth.authenticate(&realm_id, credentials).await {
        Ok(ClientAuthResult::Authenticated(client)) => client,
        Ok(ClientAuthResult::Unknown) => return client_error("invalid_client"),
        Ok(ClientAuthResult::Unauthorized) => return client_error("unauthorized_client"),
        Err(_) => return unavailable(),
    };
    if client.bearer_only {
        return client_auth::bearer_only_refused();
    }
    let claims = match verified_refresh(&state, &realm, &refresh_token).await {
        Ok(Some(claims)) => claims,
        Ok(None) => return invalid_grant("Invalid refresh token"),
        Err(_) => return unavailable(),
    };
    if claims.azp != client.client_id {
        return invalid_grant(
            "Invalid refresh token. Token client and authorized client don't match",
        );
    }
    match state
        .storage
        .logout_with_refresh_token(
            &realm_id,
            &client.client_id,
            client.revision,
            &digest(&claims.jti),
        )
        .await
    {
        Ok(RefreshLogout::Ended) => (
            StatusCode::NO_CONTENT,
            [(header::CACHE_CONTROL, "no-cache")],
        )
            .into_response(),
        Ok(RefreshLogout::UnknownToken) => invalid_grant("Invalid refresh token"),
        Err(_) => unavailable(),
    }
}

/// Handles `GET /logout`, RP-initiated logout.
pub(super) async fn get(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    browser(state, realm, params, headers).await
}

/// Verifies an ID token hint against this realm's issuer.
async fn verified_hint(
    state: &OidcState,
    realm: &str,
    hint: &str,
) -> Result<Option<VerifiedIdToken>, ()> {
    if hint.len() > 8192 {
        return Ok(None);
    }
    let permit = Arc::clone(&state.signing_slots)
        .try_acquire_owned()
        .map_err(|_| ())?;
    let signer = Arc::clone(&state.signer);
    let hint = hint.to_owned();
    let claims = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        signer.verify_id_token(&hint)
    })
    .await
    .map_err(|_| ())?;
    let issuer = format!("{}/realms/{realm}", state.issuer_base.trim_end_matches('/'));
    Ok(claims.ok().filter(|claims| claims.iss == issuer))
}

/// Marks a logout page `no-cache`, as the reference's logout endpoint
/// sends its pages.
fn no_cache(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

/// An error page of a refused logout, which the reference shows before
/// its logout session exists, so it skips `ui_locales`.
async fn refuse(
    state: &OidcState,
    realm: &str,
    realm_id: &str,
    headers: &HeaderMap,
    status: StatusCode,
    key: &str,
    args: &[&str],
) -> Response {
    let notice = Notice::error(status, key).with_args(args);
    no_cache(notice::error_page(state, realm, realm_id, headers, &notice).await)
}

/// The browser's SSO session, from its identity cookie.
async fn browser_session(
    state: &OidcState,
    realm_id: &str,
    headers: &HeaderMap,
) -> Result<Option<SsoSession>, ()> {
    match cookie(headers, "KEYCLOAK_IDENTITY") {
        Some(token) => state
            .storage
            .sso_session(realm_id, &digest(token))
            .await
            .map_err(|_| ()),
        None => Ok(None),
    }
}

/// Whether a post-logout redirect URI is registered for a client.
fn redirect_allowed(
    state: &OidcState,
    rules: &rs_keycloak_storage_postgres::RedirectRules,
    uri: &str,
) -> bool {
    let server = state.issuer_base.trim_end_matches('/');
    rules.redirect_uris.iter().any(|registered| {
        resolve_redirect(registered, rules.root_url.as_deref(), server)
            .is_some_and(|resolved| redirect_matches(&resolved, uri))
    })
}

/// Starts a browser logout, as `LogoutEndpoint.logout` decides it: a
/// client named by the ID token hint, or a matching `client_id` with a
/// hint, or a valid redirect without any session, skips the confirmation;
/// an unknown client or another session in the browser forces it.
async fn browser(
    state: OidcState,
    realm: String,
    params: BTreeMap<String, String>,
    headers: HeaderMap,
) -> Response {
    let realm_id = match realm_id(&state, &realm).await {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let client_param = params.get("client_id");
    let redirect_param = params.get("post_logout_redirect_uri");
    let hint_param = params.get("id_token_hint");
    let refused = async |status, key, args: &[&str]| {
        refuse(&state, &realm, &realm_id, &headers, status, key, args).await
    };
    if redirect_param.is_some() && hint_param.is_none() && client_param.is_none() {
        return refused(
            StatusCode::BAD_REQUEST,
            "missingParameterMessage",
            &["id_token_hint"],
        )
        .await;
    }
    let hint = match hint_param {
        None => None,
        Some(hint) => match verified_hint(&state, &realm, hint).await {
            Ok(Some(claims)) => Some(claims),
            Ok(None) => {
                return refused(
                    StatusCode::BAD_REQUEST,
                    "invalidParameterMessage",
                    &["id_token_hint"],
                )
                .await;
            }
            Err(()) => return unavailable(),
        },
    };
    let mut confirm = true;
    let mut forced = false;
    // An ID token names its client first; audience mappers add others.
    let named = client_param
        .map(String::as_str)
        .or(hint.as_ref().map(|claims| claims.aud.first()));
    let rules = match named {
        Some(client) => match state.storage.post_logout_rules(&realm_id, client).await {
            Ok(rules) => rules,
            Err(_) => return unavailable(),
        },
        None => None,
    };
    match (client_param, &hint) {
        (Some(_), _) if rules.is_none() => forced = true,
        (Some(client), Some(claims)) if claims.aud.first() != client.as_str() => {
            return refused(
                StatusCode::BAD_REQUEST,
                "invalidParameterMessage",
                &["id_token_hint"],
            )
            .await;
        }
        (Some(_), Some(_)) => confirm = false,
        (None, Some(_)) if rules.is_some() => confirm = false,
        _ => (),
    }
    let redirect = match redirect_param {
        None => None,
        Some(uri) => match Url::parse(uri) {
            Ok(url)
                if rules
                    .as_ref()
                    .is_some_and(|rules| redirect_allowed(&state, rules, uri)) =>
            {
                Some(url)
            }
            _ => return refused(StatusCode::BAD_REQUEST, "invalidRedirectUriMessage", &[]).await,
        },
    };
    let session = match browser_session(&state, &realm_id, &headers).await {
        Ok(session) => session,
        Err(()) => return unavailable(),
    };
    let hint_sid = hint.as_ref().and_then(|claims| claims.sid.clone());
    match &session {
        Some(session) => {
            if hint_sid
                .as_ref()
                .is_some_and(|sid| *sid != session.session_id)
            {
                forced = true;
            }
        }
        None => {
            if hint.is_none() && rules.is_some() && redirect.is_some() {
                confirm = false;
            }
        }
    }
    let request = LogoutRequest {
        redirect_uri: redirect.map(String::from),
        state: params
            .get("state")
            .filter(|value| value.len() <= 2048)
            .cloned(),
        ui_locales: params
            .get("ui_locales")
            .filter(|value| value.len() <= 2048)
            .cloned(),
        requested_locale: None,
        hint: hint
            .as_ref()
            .and_then(|claims| claims.sid.clone().map(|sid| (sid, claims.sub.clone()))),
    };
    if confirm || forced {
        return ask(
            &state,
            &realm,
            &realm_id,
            &request,
            session.as_ref(),
            &headers,
        )
        .await;
    }
    finish(
        &state,
        &realm,
        &realm_id,
        &request,
        session.as_ref(),
        hint.is_some(),
        &headers,
    )
    .await
}

/// The user a logout's pages read the locale of: the browser session's,
/// else the hint's.
async fn logout_user_locale(
    state: &OidcState,
    realm_id: &str,
    request: &LogoutRequest,
    session: Option<&SsoSession>,
) -> Result<Option<String>, ()> {
    if let Some(session) = session {
        return Ok(session.locale.clone());
    }
    match &request.hint {
        Some((_, user)) => state
            .storage
            .user_locale(realm_id, user)
            .await
            .map_err(|_| ()),
        None => Ok(None),
    }
}

/// The locale of a logout's pages: the pick, the user's locale, the
/// client's `ui_locales`, then this browser's.
async fn logout_locale(
    state: &OidcState,
    realm_id: &str,
    request: &LogoutRequest,
    user: Option<String>,
    headers: &HeaderMap,
) -> Result<PageLocale, ()> {
    let base = state.storage.realm_locale(realm_id).await.map_err(|_| ())?;
    let chosen = LoginLocale {
        requested: request.requested_locale.clone(),
        user,
        client: request.ui_locales.clone(),
        ..base
    };
    Ok(PageLocale::login(&chosen, headers))
}

/// The confirmation page, as `logout-confirm.ftl` shows it.
fn confirm_page(state: &OidcState, realm: &str, locale: &PageLocale, id: &str) -> Response {
    let texts = &locale.messages;
    let action = format!(
        "{}/realms/{realm}/protocol/openid-connect/logout/logout-confirm",
        state.path_prefix
    );
    let body = format!(
        "<div id=\"kc-logout-confirm\" class=\"content-area\"><p class=\"instruction\">{}</p><form class=\"form-actions\" action=\"{}\" method=\"POST\"><input type=\"hidden\" name=\"session_code\" value=\"{id}\"><input name=\"confirmLogout\" id=\"kc-logout\" type=\"submit\" value=\"{}\"></form></div>",
        texts.html("logoutConfirmHeader", &[]),
        escape(&action),
        texts.html("doLogout", &[]),
    );
    let title = texts.text("logoutConfirmTitle", &[]);
    let frame = Frame {
        heading: title.clone(),
        switch: format!("{action}?session_code={id}&kc_locale="),
    };
    no_cache(framed_page_titled(
        realm,
        locale,
        Some(&title),
        &frame,
        &body,
    ))
}

/// Keeps the logout for confirmation and asks for it.
async fn ask(
    state: &OidcState,
    realm: &str,
    realm_id: &str,
    request: &LogoutRequest,
    session: Option<&SsoSession>,
    headers: &HeaderMap,
) -> Response {
    let (id, csrf) = (random_token(), random_token());
    if state
        .storage
        .create_logout_request(realm_id, &id, &digest(&csrf), request, CONFIRM_SECONDS)
        .await
        .is_err()
    {
        return unavailable();
    }
    let Ok(user) = logout_user_locale(state, realm_id, request, session).await else {
        return unavailable();
    };
    let Ok(locale) = logout_locale(state, realm_id, request, user, headers).await else {
        return unavailable();
    };
    let mut response = confirm_page(state, realm, &locale, &id);
    let cookie = format!(
        "{CSRF_COOKIE}={csrf}; Path={}/realms/{realm}/protocol/openid-connect/logout; Max-Age={CONFIRM_SECONDS}; Secure; HttpOnly; SameSite=Strict",
        state.path_prefix
    );
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            response.headers_mut().append(header::SET_COOKIE, value);
            response
        }
        Err(_) => unavailable(),
    }
}

/// Ends the hint's and the browser's sessions, then redirects or shows the
/// logged-out page in the user's locale. `clear` expires the SSO cookies.
async fn finish(
    state: &OidcState,
    realm: &str,
    realm_id: &str,
    request: &LogoutRequest,
    session: Option<&SsoSession>,
    clear: bool,
    headers: &HeaderMap,
) -> Response {
    let Ok(user) = logout_user_locale(state, realm_id, request, session).await else {
        return unavailable();
    };
    let ended = request
        .hint
        .iter()
        .map(|(sid, sub)| (sid.as_str(), sub.as_str()))
        .chain(session.map(|session| (session.session_id.as_str(), session.user_id.as_str())));
    for (sid, sub) in ended {
        if state
            .storage
            .logout_session(realm_id, sid, sub)
            .await
            .is_err()
        {
            return unavailable();
        }
    }
    let redirect = request
        .redirect_uri
        .as_deref()
        .and_then(|uri| Url::parse(uri).ok());
    let mut response = match redirect {
        Some(mut url) => {
            if let Some(value) = &request.state {
                url.query_pairs_mut().append_pair("state", value);
            }
            (
                StatusCode::FOUND,
                [
                    (header::LOCATION, url.to_string()),
                    (header::CACHE_CONTROL, "no-cache".to_owned()),
                ],
            )
                .into_response()
        }
        None => {
            let Ok(locale) = logout_locale(state, realm_id, request, user, headers).await else {
                return unavailable();
            };
            no_cache(notice::detached(
                state,
                realm,
                &locale,
                &Notice::info("successLogout"),
            ))
        }
    };
    let clear = clear || session.is_some() || cookie(headers, "KEYCLOAK_IDENTITY").is_some();
    if clear {
        for value in sso_cookies(&state.path_prefix, realm, None) {
            if let Ok(value) = HeaderValue::from_str(&value) {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
        }
    }
    // Logout forgets a remembered username, as AuthenticationManager does.
    if cookie(headers, super::REMEMBER_ME_COOKIE).is_some()
        && let Ok(value) =
            HeaderValue::from_str(&super::remember_me_cookie(&state.path_prefix, realm, None))
    {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// The confirmation page's logout request.
#[derive(Deserialize)]
pub(super) struct ConfirmQuery {
    session_code: Option<String>,
}

/// Re-shows the confirmation in a picked locale, as `logoutConfirmGet`
/// does; once the logout is gone, shows the logged-out page, or the
/// failure while a session remains.
pub(super) async fn confirm_get(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    Query(query): Query<ConfirmQuery>,
    Query(locale_query): Query<LocaleQuery>,
    headers: HeaderMap,
) -> Response {
    let realm_id = match realm_id(&state, &realm).await {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let Ok(settings) = state.storage.user_settings(&realm_id).await else {
        return unavailable();
    };
    let picked = locale_query
        .pick()
        .filter(|_| settings.internationalization_enabled);
    let found = match (query.session_code.as_deref(), cookie(&headers, CSRF_COOKIE)) {
        (Some(id), Some(csrf)) if id.len() == 64 && csrf.len() == 64 => {
            match state
                .storage
                .logout_request(&realm_id, id, &digest(csrf), picked)
                .await
            {
                Ok(found) => found.map(|request| (id, request)),
                Err(_) => return unavailable(),
            }
        }
        _ => None,
    };
    let session = match browser_session(&state, &realm_id, &headers).await {
        Ok(session) => session,
        Err(()) => return unavailable(),
    };
    let Some((id, request)) = found else {
        if session.is_some() {
            return refuse(
                &state,
                &realm,
                &realm_id,
                &headers,
                StatusCode::BAD_REQUEST,
                "failedLogout",
                &[],
            )
            .await;
        }
        let Ok(locale) = login_locale::realm_page(&state, &realm_id, &headers).await else {
            return unavailable();
        };
        return no_cache(notice::detached(
            &state,
            &realm,
            &locale,
            &Notice::info("successLogout"),
        ));
    };
    let Ok(user) = logout_user_locale(&state, &realm_id, &request, session.as_ref()).await else {
        return unavailable();
    };
    let Ok(locale) = logout_locale(&state, &realm_id, &request, user, &headers).await else {
        return unavailable();
    };
    let cookie = picked.map(|picked| locale::cookie(&state.path_prefix, &realm, picked));
    login_locale::with_cookie(confirm_page(&state, &realm, &locale, id), cookie)
}

/// Logs out once the user confirms.
pub(super) async fn confirm_post(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    form: Result<Form<BTreeMap<String, String>>, FormRejection>,
) -> Response {
    let realm_id = match realm_id(&state, &realm).await {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let code = form
        .ok()
        .and_then(|Form(mut fields)| fields.remove("session_code"));
    let found = match (code.as_deref(), cookie(&headers, CSRF_COOKIE)) {
        (Some(id), Some(csrf)) if id.len() == 64 && csrf.len() == 64 => {
            match state
                .storage
                .take_logout_request(&realm_id, id, &digest(csrf))
                .await
            {
                Ok(found) => found,
                Err(_) => return unavailable(),
            }
        }
        _ => None,
    };
    let Some(request) = found else {
        return refuse(
            &state,
            &realm,
            &realm_id,
            &headers,
            StatusCode::BAD_REQUEST,
            "failedLogout",
            &[],
        )
        .await;
    };
    let session = match browser_session(&state, &realm_id, &headers).await {
        Ok(session) => session,
        Err(()) => return unavailable(),
    };
    let hinted = request.hint.is_some();
    finish(
        &state,
        &realm,
        &realm_id,
        &request,
        session.as_ref(),
        hinted,
        &headers,
    )
    .await
}
