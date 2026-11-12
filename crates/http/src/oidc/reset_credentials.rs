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
use serde::Deserialize;
use zeroize::Zeroizing;

use super::consent::escape;
use super::login_locale::{self, LocaleQuery};
use super::{
    Frame, LoginNotice, OidcState, Rejection, csrf, digest, failure, field_error, login_page,
    random_token, step_page, unavailable, valid_realm,
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

/// Renders the forgot-password form, with the missing-username error after
/// an empty request, as the reference does.
async fn reset_form(
    s: &OidcState,
    realm: &str,
    bound: &Bound,
    headers: &HeaderMap,
    missing: bool,
) -> Response {
    let Ok(locale) = login_locale::page(s, &bound.realm_id, &bound.request_id, headers).await
    else {
        return unavailable();
    };
    let texts = &locale.messages;
    let prefix = escape(&s.path_prefix);
    let request_id = &bound.request_id;
    let error = if missing {
        field_error("username", &texts.html("missingUsernameMessage", &[]))
    } else {
        String::new()
    };
    let body = format!(
        "<form id=\"kc-reset-password-form\" method=\"post\" action=\"{prefix}/realms/{realm}/login-actions/reset-credentials?request={request_id}\"><label for=\"username\">{username}</label><input id=\"username\" name=\"username\" autocomplete=\"username\" required>{error}<button>{submit}</button></form><p><a href=\"{prefix}/realms/{realm}/login-actions/authenticate/{request_id}\">{back}</a></p><p>{instruction}</p>",
        username = texts.html(locale.username_key(), &[]),
        submit = texts.html("doSubmit", &[]),
        back = texts.html("backToLogin", &[]),
        instruction = texts.html("emailInstruction", &[]),
    );
    let frame = Frame {
        heading: texts.text("emailForgotTitle", &[]),
        switch: format!(
            "{}/realms/{realm}/login-actions/reset-credentials?request={request_id}&kc_locale=",
            s.path_prefix
        ),
    };
    step_page(&s.path_prefix, realm, &bound.csrf, &locale, &frame, &body)
}

/// Shows the forgot-password form, after a language link's `kc_locale`
/// pick.
pub(super) async fn form(
    State(s): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<BTreeMap<String, String>>,
    Query(locale_query): Query<LocaleQuery>,
    headers: HeaderMap,
) -> Response {
    let bound = match bound(&s, &realm, &params, &headers).await {
        Ok(bound) => bound,
        Err(rejection) => return rejection.into_response(),
    };
    let picked = match login_locale::pick(
        &s,
        &realm,
        &bound.realm_id,
        &bound.request_id,
        &locale_query,
    )
    .await
    {
        Ok(picked) => picked,
        Err(()) => return unavailable(),
    };
    let response = reset_form(&s, &realm, &bound, &headers, false).await;
    login_locale::with_cookie(response, picked)
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
    let bound = match bound(&s, &realm, &params, &headers).await {
        Ok(bound) => bound,
        Err(rejection) => return rejection.into_response(),
    };
    let record = match s.storage.realm_by_name(&realm).await {
        Ok(Some(record)) if record.reset_password_allowed => record,
        Ok(_) => return failure(),
        Err(_) => return unavailable(),
    };
    let name = form.username.trim();
    if name.is_empty() {
        return reset_form(&s, &realm, &bound, &headers, true).await;
    }
    let Bound {
        realm_id,
        request_id,
        csrf,
    } = bound;
    if name.len() > 255 {
        return login_page(
            &s,
            &realm,
            &request_id,
            &csrf,
            LoginNotice::EmailSent,
            &headers,
            None,
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
                let link = crate::mail::action_link(&s, &realm, &token);
                let locale = match s.storage.user(&realm_id, &user_id).await {
                    Ok(user) => user.and_then(|user| user.locale),
                    Err(_) => return unavailable(),
                };
                let recipient = crate::mail::Recipient {
                    email: &email,
                    locale: locale.as_deref(),
                };
                // Delivery failures are not shown, so the page stays the same
                // for every username.
                let _ = crate::mail::deliver(
                    &s,
                    &record,
                    &settings,
                    &recipient,
                    &headers,
                    &crate::mail::Template::PasswordReset,
                    &link,
                    LINK_SECONDS,
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
        None,
    )
    .await
}
