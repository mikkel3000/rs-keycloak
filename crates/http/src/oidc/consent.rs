//! OAuth consent screen and its accept or cancel answer.
//!
//! Follows the recorded cases in `tests/reference/consent-observations.json`:
//! accept issues the code and remembers the consent, cancel redirects with
//! `access_denied`. The form is bound to the login request's CSRF cookie.

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::Response;
use serde::Deserialize;

use super::{
    Frame, OidcState, authorization_response, csrf, digest, failure, random_token, reshow_url,
    step_page, unavailable, valid_realm,
};
use crate::locale::PageLocale;
pub(super) use crate::login_theme::escape;

/// The consent texts of the scopes the consent page lists: every client's
/// default scopes shown on the consent screen, which are profile, email and
/// roles.
const SCOPE_TEXTS: [&str; 3] = [
    "profileScopeConsentText",
    "emailScopeConsentText",
    "rolesScopeConsentText",
];

/// Renders the consent form for a request whose CSRF cookie is `csrf`.
pub(super) fn page(
    path_prefix: &str,
    realm: &str,
    request_id: &str,
    client_identifier: &str,
    csrf: &str,
    locale: &PageLocale,
) -> Response {
    let texts = &locale.messages;
    let scopes: String = SCOPE_TEXTS
        .iter()
        .map(|key| format!("<li>{}</li>", texts.html(key, &[])))
        .collect();
    let body = format!(
        "<h2>{request}</h2><ul>{scopes}</ul><form id=\"kc-oauth\" method=\"post\" action=\"{prefix}/realms/{realm}/login-actions/consent/{request_id}\"><input type=\"submit\" name=\"accept\" id=\"kc-login\" value=\"{yes}\"><input type=\"submit\" name=\"cancel\" id=\"kc-cancel\" value=\"{no}\"></form>",
        request = texts.html("oauthGrantRequest", &[]),
        prefix = escape(path_prefix),
        yes = texts.html("doYes", &[]),
        no = texts.html("doNo", &[]),
    );
    let frame = Frame {
        heading: texts.text("oauthGrantTitle", &[client_identifier]),
        switch: reshow_url(path_prefix, realm, request_id),
    };
    step_page(path_prefix, realm, csrf, locale, &frame, &body)
}

/// The consent answer; exactly one of the two submit buttons is sent.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConsentForm {
    accept: Option<String>,
    cancel: Option<String>,
}

/// Handles the consent form submission.
pub(super) async fn answer(
    State(s): State<OidcState>,
    Path((realm, request_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> Response {
    if !valid_realm(&realm) || request_id.len() != 64 {
        return failure();
    }
    let Some(csrf) = csrf(&headers).filter(|csrf| csrf.len() == 64) else {
        return failure();
    };
    let csrf_hash = digest(csrf);
    let pending = match s.storage.pending_request(&request_id, &csrf_hash).await {
        Ok(Some(pending)) => pending,
        Ok(None) => return failure(),
        Err(_) => return unavailable(),
    };
    let issuer = format!("{}/realms/{realm}", s.issuer_base.trim_end_matches('/'));
    let mut response = match (form.accept, form.cancel) {
        (Some(_), None) => {
            match s.storage.grant_consent(&request_id, &csrf_hash).await {
                Ok(true) => (),
                Ok(false) => return failure(),
                Err(_) => return unavailable(),
            }
            let code = random_token();
            let redirect = match s
                .storage
                .issue_authorization_code(
                    &request_id,
                    &csrf_hash,
                    &pending.session_id,
                    &digest(&code),
                    60,
                )
                .await
            {
                Ok(Some(redirect)) => redirect,
                Ok(None) => return failure(),
                Err(_) => return unavailable(),
            };
            authorization_response::build(redirect, &code, &pending.session_id, &issuer)
        }
        (None, Some(_)) => match s.storage.deny_consent(&request_id, &csrf_hash).await {
            Ok(Some(redirect)) => authorization_response::error(redirect, "access_denied", &issuer),
            Ok(None) => return failure(),
            Err(_) => return unavailable(),
        },
        _ => return failure(),
    }
    .unwrap_or_else(|()| unavailable());
    let clear = format!(
        "rs_auth=; Path={}/realms/{realm}/login-actions/; Max-Age=0; Secure; HttpOnly; SameSite=Strict",
        s.path_prefix
    );
    if let Ok(value) = HeaderValue::from_str(&clear) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}
