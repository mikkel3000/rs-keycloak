//! Links sent by email: `/login-actions/action-token?key=`.
//!
//! Follows `tests/reference/execute-actions-observations.json`: the link
//! opens an info page, then the password form, then a confirmation; a used
//! or expired key answers 400. Keys are single use and stored as digests.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use rs_keycloak_storage_postgres::{ActionToken, VerifyLink};
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::consent::escape;
use super::login_locale::{self, LocaleQuery};
use super::login_steps::{Held, PasswordError, continue_login, password_form};
use super::{Frame, OidcState, csrf, digest, framed_page, plain_page, unavailable, valid_realm};

/// Session lifetime, matching password login.
const SESSION_SECONDS: i32 = 1800;

fn expired() -> Response {
    plain_page(
        StatusCode::BAD_REQUEST,
        "Action expired",
        "<p>Action expired. Please continue with login now.</p>",
    )
}

/// Why a link cannot be used.
enum Refused {
    /// Unknown, used or expired key, or an unknown realm.
    Expired,
    /// Storage could not answer.
    Unavailable,
}

impl Refused {
    fn into_response(self) -> Response {
        match self {
            Self::Expired => expired(),
            Self::Unavailable => unavailable(),
        }
    }
}

/// Resolves the realm and a live token for `key`.
async fn live(
    s: &OidcState,
    realm: &str,
    key: Option<&str>,
) -> Result<(String, ActionToken), Refused> {
    let Some(key) = key.filter(|key| key.len() == 64) else {
        return Err(Refused::Expired);
    };
    if !valid_realm(realm) {
        return Err(Refused::Expired);
    }
    let realm_id = match s.storage.realm_id_by_name(realm).await {
        Ok(Some(id)) => id,
        Ok(None) => return Err(Refused::Expired),
        Err(_) => return Err(Refused::Unavailable),
    };
    match s.storage.action_token(&realm_id, &digest(key)).await {
        Ok(Some(token)) => Ok((realm_id, token)),
        Ok(None) => Err(Refused::Expired),
        Err(_) => Err(Refused::Unavailable),
    }
}

fn link(s: &OidcState, realm: &str, key: &str) -> String {
    escape(&format!(
        "{}/realms/{realm}/login-actions/action-token?key={key}",
        s.path_prefix
    ))
}

/// The login request a token continues, when this browser started it.
async fn bound_request(
    s: &OidcState,
    token: &ActionToken,
    headers: &HeaderMap,
) -> Result<Option<String>, ()> {
    let (Some(request_id), Some(csrf)) = (
        token.authorization_request_id.as_deref(),
        csrf(headers).filter(|csrf| csrf.len() == 64),
    ) else {
        return Ok(None);
    };
    match s
        .storage
        .authorization_request_client(request_id, &digest(csrf))
        .await
    {
        Ok(found) => Ok(found.map(|_| request_id.to_owned())),
        Err(_) => Err(()),
    }
}

/// What the new-password page of a link needs.
struct PasswordLink<'a> {
    realm: &'a str,
    realm_id: &'a str,
    key: &'a str,
    /// Whether the link names its action, as admin-sent links do.
    execute: bool,
}

/// Shows the new-password form of a link in the login request's locale, or
/// the realm's in another browser, with language links that keep the key,
/// as the reference forwards it. Once the link names the user, the
/// reference's locale action runs, so a pick becomes the user's locale.
async fn password_page(
    s: &OidcState,
    link: &PasswordLink<'_>,
    token: &ActionToken,
    query: &LocaleQuery,
    headers: &HeaderMap,
    error: PasswordError,
) -> Response {
    let Ok(request) = bound_request(s, token, headers).await else {
        return unavailable();
    };
    let Ok((locale, picked)) = login_locale::link_page(
        s,
        link.realm,
        link.realm_id,
        request.as_deref(),
        query,
        headers,
    )
    .await
    else {
        return unavailable();
    };
    let adopted = match &request {
        Some(request_id) => match login_locale::adopt_for_user(
            s,
            link.realm,
            link.realm_id,
            request_id,
            &token.user_id,
            headers,
        )
        .await
        {
            Ok(adopted) => adopted,
            Err(()) => return unavailable(),
        },
        None => None,
    };
    let execute = if link.execute {
        "&execute=UPDATE_PASSWORD"
    } else {
        ""
    };
    let action = format!(
        "{}/realms/{}/login-actions/action-token?key={}{execute}",
        s.path_prefix, link.realm, link.key
    );
    let frame = Frame {
        heading: locale.messages.text("updatePasswordTitle", &[]),
        switch: format!("{action}&kc_locale="),
    };
    let body = password_form(&locale, &action, error, "resetPasswordMessage");
    let response = framed_page(link.realm, &locale, &frame, &body);
    login_locale::with_cookie(login_locale::with_cookie(response, picked), adopted)
}

/// Handles an email-verification key, or returns `None` for other keys.
///
/// In the browser that started the login the address is verified and the
/// login continues; elsewhere the user first confirms, as the reference asks.
async fn verify_email(
    s: &OidcState,
    realm: &str,
    key: Option<&str>,
    params: &BTreeMap<String, String>,
    headers: &HeaderMap,
) -> Option<Response> {
    let key = key.filter(|key| key.len() == 64)?;
    if !valid_realm(realm) {
        return None;
    }
    let realm_id = match s.storage.realm_id_by_name(realm).await {
        Ok(Some(id)) => id,
        Ok(None) => return None,
        Err(_) => return Some(unavailable()),
    };
    let hash = digest(key);
    let request = match s.storage.verify_link(&realm_id, &hash).await {
        Ok(VerifyLink::Live {
            authorization_request_id,
        }) => authorization_request_id,
        Ok(VerifyLink::AlreadyVerified) => {
            return Some(plain_page(
                StatusCode::OK,
                "Email verified",
                "<p>Your email address has been verified already.</p>",
            ));
        }
        Ok(VerifyLink::Unknown) => return None,
        Err(_) => return Some(unavailable()),
    };
    if let (Some(request_id), Some(csrf)) = (
        request.as_deref(),
        csrf(headers).filter(|csrf| csrf.len() == 64),
    ) {
        match s.storage.pending_request(request_id, &digest(csrf)).await {
            Ok(Some(pending)) => {
                return Some(
                    match s
                        .storage
                        .redeem_verify_link(&realm_id, &hash, Some(&pending.session_id))
                        .await
                    {
                        Ok(true) => {
                            let held = Held {
                                realm_id: realm_id.clone(),
                                session_id: pending.session_id,
                                csrf: csrf.to_owned(),
                            };
                            continue_login(s, realm, request_id, &held, headers).await
                        }
                        Ok(false) => expired(),
                        Err(_) => unavailable(),
                    },
                );
            }
            Ok(None) => (),
            Err(_) => return Some(unavailable()),
        }
    }
    if params.get("confirm").map(String::as_str) == Some("1") {
        return Some(
            match s.storage.redeem_verify_link(&realm_id, &hash, None).await {
                Ok(true) => plain_page(
                    StatusCode::OK,
                    "Email verified",
                    "<p>Your email address has been verified.</p>",
                ),
                Ok(false) => expired(),
                Err(_) => unavailable(),
            },
        );
    }
    let body = format!(
        "<h1>Confirm validity of e-mail address</h1><p><a href=\"{proceed}&amp;confirm=1\">Click here to proceed</a></p>",
        proceed = link(s, realm, key),
    );
    Some(plain_page(
        StatusCode::OK,
        "Confirm validity of e-mail address",
        &body,
    ))
}

/// Shows the info page, or the password form once the user proceeds.
pub(super) async fn show(
    State(s): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<BTreeMap<String, String>>,
    Query(locale_query): Query<LocaleQuery>,
    headers: HeaderMap,
) -> Response {
    let key = params.get("key").map(String::as_str);
    if let Some(response) = verify_email(&s, &realm, key, &params, &headers).await {
        return response;
    }
    let (realm_id, token) = match live(&s, &realm, key).await {
        Ok(found) => found,
        Err(refused) => return refused.into_response(),
    };
    let key = key.unwrap_or_default();
    // A link requested from the login page opens the form directly; an
    // admin-sent link first lists the requested actions.
    let execute = params.get("execute").map(String::as_str) == Some("UPDATE_PASSWORD");
    if token.from_login || execute {
        let link = PasswordLink {
            realm: &realm,
            realm_id: &realm_id,
            key,
            execute,
        };
        return password_page(
            &s,
            &link,
            &token,
            &locale_query,
            &headers,
            PasswordError::None,
        )
        .await;
    }
    let body = format!(
        "<h1>Perform the following action</h1><ul><li>Update Password</li></ul><p><a href=\"{proceed}&amp;execute=UPDATE_PASSWORD\">Click here to proceed</a></p>",
        proceed = link(&s, &realm, key),
    );
    plain_page(StatusCode::OK, "Perform the following action", &body)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasswordForm {
    #[serde(rename = "password-new")]
    password_new: String,
    #[serde(rename = "password-confirm")]
    password_confirm: String,
    #[serde(rename = "logout-sessions")]
    logout_sessions: Option<String>,
}

/// Sets the new password and uses up the key.
pub(super) async fn submit(
    State(s): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<BTreeMap<String, String>>,
    Query(locale_query): Query<LocaleQuery>,
    headers: HeaderMap,
    Form(form): Form<PasswordForm>,
) -> Response {
    let key = params.get("key").map(String::as_str);
    let (realm_id, token) = match live(&s, &realm, key).await {
        Ok(found) => found,
        Err(refused) => return refused.into_response(),
    };
    let key = key.unwrap_or_default();
    let password = Zeroizing::new(form.password_new);
    let confirm = Zeroizing::new(form.password_confirm);
    let error = PasswordError::check(&password, &confirm);
    if error != PasswordError::None {
        let link = PasswordLink {
            realm: &realm,
            realm_id: &realm_id,
            key,
            execute: params.get("execute").map(String::as_str) == Some("UPDATE_PASSWORD"),
        };
        return password_page(&s, &link, &token, &locale_query, &headers, error).await;
    }
    let Ok(permit) = Arc::clone(&s.hash_slots).try_acquire_owned() else {
        return unavailable();
    };
    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        rs_keycloak_crypto::hash_password(password.as_bytes())
    })
    .await;
    let Ok(Ok(hash)) = hash else {
        return unavailable();
    };
    let hash = Zeroizing::new(hash);
    let redeemed = match s
        .storage
        .redeem_password_token(
            &realm_id,
            &digest(key),
            &Uuid::new_v4().to_string(),
            hash.as_bytes(),
        )
        .await
    {
        Ok(Some(redeemed)) => redeemed,
        Ok(None) => return expired(),
        Err(_) => return unavailable(),
    };
    if form.logout_sessions.as_deref() == Some("on")
        && s.storage
            .end_user_sessions(&realm_id, &token.user_id)
            .await
            .is_err()
    {
        return unavailable();
    }
    // The browser that asked for the link continues its login, as the
    // reference does; the emailed link stands in for the password.
    if let (Some(request_id), Some(csrf)) = (
        redeemed.authorization_request_id.as_deref(),
        csrf(&headers).filter(|csrf| csrf.len() == 64),
    ) {
        let session_id = Uuid::new_v4().to_string();
        match s
            .storage
            .start_session_for_request(
                &realm_id,
                request_id,
                &digest(csrf),
                &redeemed.user_id,
                &session_id,
                SESSION_SECONDS,
            )
            .await
        {
            Ok(true) => {
                let held = Held {
                    realm_id,
                    session_id,
                    csrf: csrf.to_owned(),
                };
                return continue_login(&s, &realm, request_id, &held, &headers).await;
            }
            Ok(false) => (),
            Err(_) => return unavailable(),
        }
    }
    plain_page(
        StatusCode::OK,
        "Account updated",
        "<p>Your account has been updated.</p>",
    )
}
