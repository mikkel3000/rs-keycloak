//! Forgot-password from the login page.
//!
//! Follows `tests/reference/reset-credentials-observations.json`: the form
//! asks for a username or email, and every request gets the same login page
//! back, so the flow does not reveal which accounts exist. Known users with
//! an email get a single-use link bound to this login request.

use std::collections::BTreeMap;

use axum::extract::{Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use rs_keycloak_integrations::mail::{Mail, send};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::consent::escape;
use super::login_locale;
use super::{
    LoginNotice, OidcState, Rejection, csrf, digest, failure, login_page, random_token, step_page,
    unavailable, valid_realm,
};

/// Lifespan of a user-requested link, as Keycloak's default (5 minutes).
const LINK_SECONDS: i32 = 300;

/// The login request a reset belongs to.
struct Bound {
    realm_id: String,
    request_id: String,
    csrf: String,
}

/// Resolves the login request after the CSRF check.
async fn bound(
    s: &OidcState,
    realm: &str,
    params: &BTreeMap<String, String>,
    headers: &HeaderMap,
) -> Result<Bound, Rejection> {
    let request_id = params.get("request").filter(|id| id.len() == 64);
    let csrf = csrf(headers).filter(|csrf| csrf.len() == 64);
    let (Some(request_id), Some(csrf)) = (request_id, csrf) else {
        return Err(Rejection::Invalid);
    };
    if !valid_realm(realm) {
        return Err(Rejection::Invalid);
    }
    match s
        .storage
        .authorization_request_client(request_id, &digest(csrf))
        .await
    {
        Ok(Some((realm_id, _))) => Ok(Bound {
            realm_id,
            request_id: request_id.clone(),
            csrf: csrf.to_owned(),
        }),
        Ok(None) => Err(Rejection::Invalid),
        Err(_) => Err(Rejection::Unavailable),
    }
}

/// Shows the forgot-password form.
pub(super) async fn form(
    State(s): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let Bound {
        realm_id,
        request_id,
        csrf,
    } = match bound(&s, &realm, &params, &headers).await {
        Ok(bound) => bound,
        Err(rejection) => return rejection.into_response(),
    };
    let Ok(locale) = login_locale::page(&s, &realm_id, &request_id, &headers).await else {
        return unavailable();
    };
    let body = format!(
        "<h1>Forgot your password?</h1><form id=\"kc-reset-password-form\" method=\"post\" action=\"{prefix}/realms/{realm}/login-actions/reset-credentials?request={request_id}\"><label>Username or email <input name=\"username\" autocomplete=\"username\" required></label><button>Submit</button></form>",
        prefix = escape(&s.path_prefix),
    );
    step_page(
        &s.path_prefix,
        &realm,
        &csrf,
        &locale,
        "Forgot your password?",
        &body,
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResetForm {
    username: String,
}

/// Sends the link to a known user and answers every request the same way.
pub(super) async fn request(
    State(s): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
    Form(form): Form<ResetForm>,
) -> Response {
    let Bound {
        realm_id,
        request_id,
        csrf,
    } = match bound(&s, &realm, &params, &headers).await {
        Ok(bound) => bound,
        Err(rejection) => return rejection.into_response(),
    };
    let record = match s.storage.realm_by_name(&realm).await {
        Ok(Some(record)) if record.reset_password_allowed => record,
        Ok(_) => return failure(),
        Err(_) => return unavailable(),
    };
    let name = form.username.trim();
    if name.is_empty() || name.len() > 255 {
        return login_page(
            &s,
            &realm,
            &request_id,
            &csrf,
            LoginNotice::EmailSent,
            &headers,
        )
        .await;
    }
    let target = match s.storage.reset_target(&realm_id, name).await {
        Ok(target) => target,
        Err(_) => return unavailable(),
    };
    let settings = crate::mail::settings(&record);
    if let (Some((user_id, email)), Some(settings)) = (target, settings) {
        let token = Zeroizing::new(random_token());
        let actions = ["UPDATE_PASSWORD".to_owned()];
        match s
            .storage
            .issue_action_token(
                &realm_id,
                &user_id,
                &digest(&token),
                &actions,
                LINK_SECONDS,
                Some(&request_id),
            )
            .await
        {
            Ok(true) => {
                let link = format!(
                    "{}/realms/{realm}/login-actions/action-token?key={}",
                    s.issuer_base.trim_end_matches('/'),
                    *token
                );
                let text = format!(
                    "Someone just requested to change your {realm} account's credentials. If this was you, click on the link below to reset them.\n\n{link}\n\nThis link and code will expire within 5 minutes.\n\nIf you don't want to reset your credentials, just ignore this message and nothing will be changed."
                );
                let html = format!(
                    "<p>Someone just requested to change your {realm} account's credentials. If this was you, click on the link below to reset them.</p><p><a href=\"{link}\">Link to reset credentials</a></p><p>This link and code will expire within 5 minutes.</p><p>If you don't want to reset your credentials, just ignore this message and nothing will be changed.</p>",
                    realm = escape(&realm),
                    link = escape(&link),
                );
                // Delivery failures are not shown, so the page stays the same
                // for every username.
                let _ = send(
                    &settings,
                    Mail {
                        to: &email,
                        subject: "Reset password",
                        text,
                        html,
                    },
                )
                .await;
            }
            Ok(false) => (),
            Err(_) => return unavailable(),
        }
    }
    login_page(
        &s,
        &realm,
        &request_id,
        &csrf,
        LoginNotice::EmailSent,
        &headers,
    )
    .await
}
