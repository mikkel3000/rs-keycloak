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
    OidcState, authorization_response, csrf, digest, failure, random_token, step_page, unavailable,
    valid_realm,
};

pub(super) fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Renders the consent form for a request whose CSRF cookie is `csrf`.
pub(super) fn page(
    path_prefix: &str,
    realm: &str,
    request_id: &str,
    client_identifier: &str,
    scope: &str,
    csrf: &str,
) -> Response {
    let body = format!(
        "<h1>Grant access to {client}</h1><p>Requested scope: {scope}</p><form id=\"kc-oauth\" method=\"post\" action=\"{prefix}/realms/{realm}/login-actions/consent/{request_id}\"><input type=\"submit\" name=\"accept\" value=\"Yes\"><input type=\"submit\" name=\"cancel\" value=\"No\"></form>",
        client = escape(client_identifier),
        scope = escape(scope),
        prefix = escape(path_prefix),
    );
    step_page(path_prefix, realm, csrf, "Grant access", &body)
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
