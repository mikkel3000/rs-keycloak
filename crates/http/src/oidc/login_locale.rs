//! The locale of a login: a `kc_locale` pick on login-actions URLs, the
//! locale of each login and required-action page, and the `KEYCLOAK_LOCALE`
//! cookie and user locale that a login leaves.
//!
//! Follows `LocaleUtil.processLocaleParam`, `UpdateUserLocaleAction` and
//! `DefaultLocaleUpdaterProvider` at the pinned revision, and
//! `tests/reference/login-settings-observations.json`.

use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::Response;
use serde::Deserialize;

use super::{OidcState, cookie};
use crate::locale::{self, PageLocale};

/// The `kc_locale` query parameter of a login-actions URL.
#[derive(Deserialize)]
pub(super) struct LocaleQuery {
    kc_locale: Option<String>,
}

/// Keeps a `kc_locale` pick for the rest of the request when the realm is
/// internationalized, and returns the cookie that remembers it. Picks that
/// are not cookie-safe tags are ignored.
pub(super) async fn pick(
    s: &OidcState,
    realm: &str,
    realm_id: &str,
    request_id: &str,
    query: &LocaleQuery,
) -> Result<Option<String>, ()> {
    let Some(picked) = query
        .kc_locale
        .as_deref()
        .filter(|picked| locale::acceptable_pick(picked))
    else {
        return Ok(None);
    };
    let settings = s.storage.user_settings(realm_id).await.map_err(|_| ())?;
    if !settings.internationalization_enabled {
        return Ok(None);
    }
    let kept = s
        .storage
        .request_locale(realm_id, request_id, picked)
        .await
        .map_err(|_| ())?;
    Ok(kept.then(|| locale::cookie(&s.path_prefix, realm, picked)))
}

/// The locale of a page of a live request; English when the request is
/// gone.
pub(super) async fn page(
    s: &OidcState,
    realm_id: &str,
    request_id: &str,
    headers: &HeaderMap,
) -> Result<PageLocale, ()> {
    let state = s
        .storage
        .login_locale(realm_id, request_id)
        .await
        .map_err(|_| ())?;
    Ok(state.map_or_else(PageLocale::english, |state| {
        PageLocale::login(&state, headers)
    }))
}

/// The reference's locale required action, run once the user is known: a
/// pick that differs from the user's locale becomes theirs and is
/// remembered; else the user's locale is remembered; else a remembered
/// locale is forgotten. Returns the cookie header to send, if any.
pub(super) async fn adopt(
    s: &OidcState,
    realm: &str,
    realm_id: &str,
    request_id: &str,
    session_id: &str,
    headers: &HeaderMap,
) -> Result<Option<String>, ()> {
    let Some(update) = s
        .storage
        .apply_requested_locale(realm_id, request_id, session_id)
        .await
        .map_err(|_| ())?
    else {
        return Ok(None);
    };
    let prefix = &s.path_prefix;
    Ok(match (update.requested, update.previous) {
        (Some(picked), previous) => {
            (previous.as_ref() != Some(&picked)).then(|| locale::cookie(prefix, realm, &picked))
        }
        (None, Some(own)) => Some(locale::cookie(prefix, realm, &own)),
        (None, None) => {
            cookie(headers, locale::COOKIE).map(|_| locale::expired_cookie(prefix, realm))
        }
    })
}

/// Adds a locale cookie header unless the response already sets one, as
/// the reference sends one per response.
pub(super) fn with_cookie(mut response: Response, value: Option<String>) -> Response {
    let Some(value) = value else {
        return response;
    };
    let prefix = format!("{}=", locale::COOKIE);
    let headers = response.headers_mut();
    let present = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|set| set.as_bytes().starts_with(prefix.as_bytes()));
    if !present && let Ok(value) = HeaderValue::from_str(&value) {
        headers.append(header::SET_COOKIE, value);
    }
    response
}
