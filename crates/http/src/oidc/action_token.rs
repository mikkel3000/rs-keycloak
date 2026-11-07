//! Links sent by email: `/login-actions/action-token?key=`.
//!
//! Follows `tests/reference/execute-actions-observations.json` and
//! `tests/reference/login-info-page-observations.json`: an admin-sent link
//! opens the list of its actions, then the password form, then a
//! confirmation; a verification link opens a confirmation, then verifies; a
//! used or expired key shows the reference's error page. Keys are single
//! use and stored as digests.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use rs_keycloak_storage_postgres::{ActionToken, LinkUser, TokenLookup, VerifyLink};
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::login_locale::{self, LocaleQuery};
use super::login_steps::{Held, PasswordError, continue_login, password_form};
use super::notice::{self, Extras, Notice};
use super::{Frame, OidcState, csrf, digest, framed_page, unavailable, valid_realm};

/// Session lifetime, matching password login.
const SESSION_SECONDS: i32 = 1800;

/// The page a key that is not live shows: the reference's error for a
/// used or expired token, with a link back to the account console it
/// sends users to, or for a key it cannot read.
async fn refused(
    s: &OidcState,
    realm: &str,
    realm_id: &str,
    spent: bool,
    headers: &HeaderMap,
) -> Response {
    let notice = if spent {
        Notice::error(StatusCode::BAD_REQUEST, "expiredActionMessage").with_back(account(s, realm))
    } else {
        Notice::error(StatusCode::BAD_REQUEST, "invalidCodeMessage")
    };
    notice::error_page(s, realm, realm_id, headers, &notice).await
}

/// The account console, the application of admin-sent links.
fn account(s: &OidcState, realm: &str) -> String {
    format!(
        "{}/realms/{realm}/account/",
        s.issuer_base.trim_end_matches('/')
    )
}

/// A link's realm and key, once the realm exists.
struct Link<'a> {
    realm: &'a str,
    realm_id: String,
    key: &'a str,
}

impl Link<'_> {
    fn url(&self, s: &OidcState) -> String {
        format!(
            "{}/realms/{}/login-actions/action-token?key={}",
            s.path_prefix, self.realm, self.key
        )
    }

    fn hash(&self) -> [u8; 32] {
        digest(self.key)
    }
}

/// Why a link cannot be used.
enum Refused {
    /// The realm is malformed or unknown.
    Invalid,
    /// Storage could not answer.
    Unavailable,
    /// The token was used or has expired.
    Spent,
    /// No such token was issued.
    Unreadable,
}

impl Refused {
    /// The page that refuses the link; `link` is known unless the realm
    /// was refused.
    async fn respond(
        self,
        s: &OidcState,
        link: Option<&Link<'_>>,
        headers: &HeaderMap,
    ) -> Response {
        match (self, link) {
            (Self::Spent, Some(link)) => {
                refused(s, link.realm, &link.realm_id, true, headers).await
            }
            (Self::Unreadable, Some(link)) => {
                refused(s, link.realm, &link.realm_id, false, headers).await
            }
            (Self::Unavailable, _) => unavailable(),
            _ => super::failure(),
        }
    }
}

/// Resolves a link's realm.
async fn link<'a>(
    s: &OidcState,
    realm: &'a str,
    key: Option<&'a str>,
) -> Result<Link<'a>, Refused> {
    if !valid_realm(realm) {
        return Err(Refused::Invalid);
    }
    let realm_id = match s.storage.realm_id_by_name(realm).await {
        Ok(Some(id)) => id,
        Ok(None) => return Err(Refused::Invalid),
        Err(_) => return Err(Refused::Unavailable),
    };
    Ok(Link {
        realm,
        realm_id,
        key: key.filter(|key| key.len() == 64).unwrap_or_default(),
    })
}

/// The live token of a link.
async fn live(s: &OidcState, link: &Link<'_>) -> Result<ActionToken, Refused> {
    if link.key.is_empty() {
        return Err(Refused::Unreadable);
    }
    match s.storage.action_token(&link.realm_id, &link.hash()).await {
        Ok(TokenLookup::Live(token)) => Ok(token),
        Ok(TokenLookup::Spent) => Err(Refused::Spent),
        Ok(TokenLookup::Unknown) => Err(Refused::Unreadable),
        Err(_) => Err(Refused::Unavailable),
    }
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

/// Shows the new-password form of a link: in the login request's locale
/// when this browser started it, else in the user's with the pick the
/// link's pages keep. Language links keep the key, as the reference
/// forwards it. Once the link names the user, the reference's locale
/// action runs, so a pick becomes the user's locale.
async fn password_page(
    s: &OidcState,
    link: &Link<'_>,
    execute: bool,
    token: &ActionToken,
    query: &LocaleQuery,
    headers: &HeaderMap,
    error: PasswordError,
) -> Response {
    let Ok(request) = bound_request(s, token, headers).await else {
        return unavailable();
    };
    let shown = match &request {
        Some(request_id) => {
            let Ok((locale, picked)) = login_locale::link_page(
                s,
                link.realm,
                &link.realm_id,
                Some(request_id),
                query,
                headers,
            )
            .await
            else {
                return unavailable();
            };
            let Ok(adopted) = login_locale::adopt_for_user(
                s,
                link.realm,
                &link.realm_id,
                request_id,
                &token.user_id,
                headers,
            )
            .await
            else {
                return unavailable();
            };
            (locale, picked, adopted, String::new())
        }
        None if token.from_login => {
            let Ok((locale, picked)) =
                login_locale::link_page(s, link.realm, &link.realm_id, None, query, headers).await
            else {
                return unavailable();
            };
            (locale, picked, None, String::new())
        }
        None => {
            let Ok(page) = token_page(s, link, token, query, headers).await else {
                return unavailable();
            };
            let Ok(adopted) = login_locale::adopt_for_token(
                s,
                link.realm,
                &link.realm_id,
                &link.hash(),
                page.requested.as_deref(),
                headers,
            )
            .await
            else {
                return unavailable();
            };
            let carried = page.carried();
            (page.page, page.picked, adopted, carried)
        }
    };
    let (locale, picked, adopted, carried) = shown;
    let execute = if execute {
        "&execute=UPDATE_PASSWORD"
    } else {
        ""
    };
    let action = format!("{}{execute}{carried}", link.url(s));
    let frame = Frame {
        heading: locale.messages.text("updatePasswordTitle", &[]),
        switch: format!("{action}&kc_locale="),
    };
    let body = password_form(&locale, &action, error, "resetPasswordMessage");
    let response = framed_page(link.realm, &locale, &frame, &body);
    login_locale::with_cookie(login_locale::with_cookie(response, picked), adopted)
}

/// The locales of an admin-sent link's page.
async fn token_page(
    s: &OidcState,
    link: &Link<'_>,
    token: &ActionToken,
    query: &LocaleQuery,
    headers: &HeaderMap,
) -> Result<login_locale::TokenPage, ()> {
    login_locale::token_page(
        s,
        link.realm,
        &link.realm_id,
        token.user_locale.as_deref(),
        query,
        headers,
    )
    .await
}

/// The locales of a verification link's page.
async fn verify_page(
    s: &OidcState,
    link: &Link<'_>,
    user: &LinkUser,
    query: &LocaleQuery,
    headers: &HeaderMap,
) -> Result<login_locale::TokenPage, ()> {
    login_locale::token_page(
        s,
        link.realm,
        &link.realm_id,
        user.locale.as_deref(),
        query,
        headers,
    )
    .await
}

/// The page a link's required actions end on outside its login, as the
/// reference's `AuthenticationManager` shows it once no step is left.
fn account_updated(s: &OidcState, realm: &str, page: &login_locale::TokenPage) -> Response {
    let notice = Notice::info("accountUpdatedMessage");
    notice::detached_with_heading(
        s,
        realm,
        &page.page,
        &notice,
        Some("accountUpdatedTitle".to_owned()),
    )
}

/// Handles an email-verification key, or returns `None` for other keys.
///
/// In the browser that started the login the address is verified and the
/// login continues; elsewhere the user first confirms, as the reference
/// asks. Headings come from the reference's text formatted before the user
/// is known, so they skip the user's locale.
async fn verify_email(
    s: &OidcState,
    link: &Link<'_>,
    params: &BTreeMap<String, String>,
    query: &LocaleQuery,
    headers: &HeaderMap,
) -> Option<Response> {
    if link.key.is_empty() {
        return None;
    }
    let hash = link.hash();
    let realm_id = &link.realm_id;
    let (request, user) = match s.storage.verify_link(realm_id, &hash).await {
        Ok(VerifyLink::Live {
            authorization_request_id,
            user,
        }) => (authorization_request_id, user),
        Ok(VerifyLink::AlreadyVerified(user)) => {
            let Ok(page) = verify_page(s, link, &user, query, headers).await else {
                return Some(unavailable());
            };
            let notice = Notice::info("emailVerifiedAlreadyMessage")
                .with_args(&[&user.email])
                .with_back(account(s, link.realm));
            let extras = Extras {
                heading: Some(
                    page.anonymous
                        .messages
                        .text("emailVerifiedAlreadyMessageHeader", &[&user.email]),
                ),
                ..Extras::default()
            };
            let response = notice::attached(
                link.realm,
                &page.page,
                &notice,
                &extras,
                format!("{}&kc_locale=", link.url(s)),
            );
            return Some(login_locale::with_cookie(response, page.picked));
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
                        .redeem_verify_link(realm_id, &hash, Some(&pending.session_id))
                        .await
                    {
                        Ok(true) => {
                            let held = Held {
                                realm_id: realm_id.clone(),
                                session_id: pending.session_id,
                                csrf: csrf.to_owned(),
                            };
                            continue_login(s, link.realm, request_id, &held, headers).await
                        }
                        Ok(false) => refused(s, link.realm, realm_id, true, headers).await,
                        Err(_) => unavailable(),
                    },
                );
            }
            Ok(None) => (),
            Err(_) => return Some(unavailable()),
        }
    }
    let Ok(page) = verify_page(s, link, &user, query, headers).await else {
        return Some(unavailable());
    };
    if params.get("confirm").map(String::as_str) == Some("1") {
        return Some(
            match s.storage.redeem_verify_link(realm_id, &hash, None).await {
                Ok(true) => {
                    let Ok(adopted) = login_locale::adopt_for_token(
                        s,
                        link.realm,
                        realm_id,
                        &hash,
                        page.requested.as_deref(),
                        headers,
                    )
                    .await
                    else {
                        return Some(unavailable());
                    };
                    let response = account_updated(s, link.realm, &page);
                    login_locale::with_cookie(
                        login_locale::with_cookie(response, page.picked),
                        adopted,
                    )
                }
                Ok(false) => refused(s, link.realm, realm_id, true, headers).await,
                Err(_) => unavailable(),
            },
        );
    }
    let notice = Notice::info("confirmEmailAddressVerification").with_args(&[&user.email]);
    let extras = Extras {
        heading: Some(
            page.anonymous
                .messages
                .text("confirmEmailAddressVerificationHeader", &[&user.email]),
        ),
        proceed: Some(format!("{}&confirm=1{}", link.url(s), page.carried())),
        ..Extras::default()
    };
    let response = notice::attached(
        link.realm,
        &page.page,
        &notice,
        &extras,
        format!("{}&kc_locale=", link.url(s)),
    );
    Some(login_locale::with_cookie(response, page.picked))
}

/// Shows the action list, or the password form once the user proceeds.
pub(super) async fn show(
    State(s): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<BTreeMap<String, String>>,
    Query(locale_query): Query<LocaleQuery>,
    headers: HeaderMap,
) -> Response {
    let link = match link(&s, &realm, params.get("key").map(String::as_str)).await {
        Ok(link) => link,
        Err(refused) => return refused.respond(&s, None, &headers).await,
    };
    if let Some(response) = verify_email(&s, &link, &params, &locale_query, &headers).await {
        return response;
    }
    let token = match live(&s, &link).await {
        Ok(token) => token,
        Err(refused) => return refused.respond(&s, Some(&link), &headers).await,
    };
    // A link requested from the login page opens the form directly; an
    // admin-sent link first lists the requested actions.
    let execute = params.get("execute").map(String::as_str) == Some("UPDATE_PASSWORD");
    if token.from_login || execute {
        return password_page(
            &s,
            &link,
            execute,
            &token,
            &locale_query,
            &headers,
            PasswordError::None,
        )
        .await;
    }
    let Ok(page) = token_page(&s, &link, &token, &locale_query, &headers).await else {
        return unavailable();
    };
    let notice = Notice::info("confirmExecutionOfActions");
    let extras = Extras {
        actions: token.actions.clone(),
        proceed: Some(format!(
            "{}&execute=UPDATE_PASSWORD{}",
            link.url(&s),
            page.carried()
        )),
        ..Extras::default()
    };
    let response = notice::attached(
        &realm,
        &page.page,
        &notice,
        &extras,
        format!("{}&kc_locale=", link.url(&s)),
    );
    login_locale::with_cookie(response, page.picked)
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
    let link = match link(&s, &realm, params.get("key").map(String::as_str)).await {
        Ok(link) => link,
        Err(refused) => return refused.respond(&s, None, &headers).await,
    };
    let token = match live(&s, &link).await {
        Ok(token) => token,
        Err(refused) => return refused.respond(&s, Some(&link), &headers).await,
    };
    let password = Zeroizing::new(form.password_new);
    let confirm = Zeroizing::new(form.password_confirm);
    let error = PasswordError::check(&password, &confirm);
    if error != PasswordError::None {
        let execute = params.get("execute").map(String::as_str) == Some("UPDATE_PASSWORD");
        return password_page(&s, &link, execute, &token, &locale_query, &headers, error).await;
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
    let realm_id = link.realm_id.clone();
    let redeemed = match s
        .storage
        .redeem_password_token(
            &realm_id,
            &link.hash(),
            &Uuid::new_v4().to_string(),
            hash.as_bytes(),
        )
        .await
    {
        Ok(Some(redeemed)) => redeemed,
        Ok(None) => return refused(&s, &realm, &realm_id, true, &headers).await,
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
    let Ok(page) = token_page(&s, &link, &token, &locale_query, &headers).await else {
        return unavailable();
    };
    login_locale::with_cookie(account_updated(&s, &realm, &page), page.picked)
}
