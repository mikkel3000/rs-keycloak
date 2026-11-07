//! Info and error pages, as the reference's `info.ftl` and `error.ftl` show
//! them, and `login-actions/detached-info`, which re-shows one in another
//! locale once no login is left to re-show it from.
//!
//! Follows `FreeMarkerLoginFormsProvider`, `DetachedInfoStateChecker` and
//! `LoginActionsService.detachedInfo` at the pinned revision, and
//! `tests/reference/login-info-page-observations.json`. As there, a
//! detached page's language links carry a fresh state that must match the
//! `KC_STATE_CHECKER` cookie, which holds the message and is sealed with a
//! key derived from the signing key.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use super::login_locale::{self, LocaleQuery};
use super::{
    Frame, OidcState, cookie, failure, framed_page, random_token, unavailable, valid_realm,
};
use crate::locale::PageLocale;
use crate::login_theme::escape;

/// The cookie that holds a detached page's message.
const STATE_COOKIE: &str = "KC_STATE_CHECKER";

/// How long a detached page can be re-shown, the reference's default
/// user-action lifespan.
const STATE_SECONDS: u32 = 300;

/// What an info or error page says: a theme message and its arguments.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Notice {
    #[serde(rename = "mky")]
    key: String,
    #[serde(rename = "mpar", default)]
    args: Vec<String>,
    #[serde(rename = "err")]
    error: bool,
    #[serde(rename = "stat")]
    status: u16,
    /// The back-to-application link.
    #[serde(rename = "back", default)]
    back: Option<String>,
}

impl Notice {
    /// An info page with a 200 status.
    pub(super) fn info(key: &str) -> Self {
        Self {
            key: key.to_owned(),
            args: Vec::new(),
            error: false,
            status: StatusCode::OK.as_u16(),
            back: None,
        }
    }

    /// An error page.
    pub(super) fn error(status: StatusCode, key: &str) -> Self {
        Self {
            error: true,
            status: status.as_u16(),
            ..Self::info(key)
        }
    }

    /// The message's arguments.
    pub(super) fn with_args(mut self, args: &[&str]) -> Self {
        self.args = args.iter().map(|arg| (*arg).to_owned()).collect();
        self
    }

    /// A back-to-application link, as pages with a client show it.
    pub(super) fn with_back(mut self, url: String) -> Self {
        self.back = Some(url);
        self
    }

    fn summary(&self, locale: &PageLocale) -> String {
        let args: Vec<&str> = self.args.iter().map(String::as_str).collect();
        locale.messages.text(&self.key, &args)
    }

    fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.status).unwrap_or(StatusCode::BAD_REQUEST)
    }
}

/// What an info page shows besides its message.
#[derive(Default)]
pub(super) struct Extras {
    /// A heading in place of the message (`messageHeader`): a message key,
    /// or a text, which is read as its own pattern.
    pub(super) heading: Option<String>,
    /// Required actions listed after the message.
    pub(super) actions: Vec<String>,
    /// The link onwards, in place of the back link.
    pub(super) proceed: Option<String>,
}

/// The page's heading and body.
fn render(locale: &PageLocale, notice: &Notice, extras: &Extras) -> (String, String) {
    let texts = &locale.messages;
    let summary = notice.summary(locale);
    let link = |href: &str, key: &str| {
        format!(
            "<p><a href=\"{}\">{}</a></p>",
            escape(href),
            texts.html(key, &[])
        )
    };
    if notice.error {
        let back = notice
            .back
            .as_deref()
            .map(|href| link(href, "backToApplication"))
            .unwrap_or_default();
        let body = format!(
            "<div id=\"kc-error-message\"><p class=\"instruction\">{}</p>{back}</div>",
            escape(&summary)
        );
        return (texts.text("errorTitle", &[]), body);
    }
    let actions = if extras.actions.is_empty() {
        String::new()
    } else {
        let names: Vec<String> = extras
            .actions
            .iter()
            .map(|action| texts.html(&format!("requiredAction.{action}"), &[]))
            .collect();
        format!(": <b>{}</b>", names.join(", "))
    };
    let onwards = match (&extras.proceed, &notice.back) {
        (Some(href), _) => link(href, "proceedWithAction"),
        (None, Some(href)) => link(href, "backToApplication"),
        (None, None) => String::new(),
    };
    let body = format!(
        "<div id=\"kc-info-message\"><p class=\"instruction\">{}{actions}</p>{onwards}</div>",
        escape(&summary)
    );
    // `info.ftl` reads the heading as a message key, so a formatted text
    // is formatted again as its own pattern.
    let heading = match &extras.heading {
        Some(heading) => texts.text(heading, &[]),
        None => summary,
    };
    (heading, body)
}

/// A page whose language links re-show it from its own URL, `switch`,
/// which ends in `kc_locale=`.
pub(super) fn attached(
    realm: &str,
    locale: &PageLocale,
    notice: &Notice,
    extras: &Extras,
    switch: String,
) -> Response {
    let (heading, body) = render(locale, notice, extras);
    let mut response = framed_page(realm, locale, &Frame { heading, switch }, &body);
    *response.status_mut() = notice.status();
    response
}

/// The sealed content of the state cookie.
#[derive(Deserialize, Serialize)]
struct DetachedState {
    #[serde(flatten)]
    notice: Notice,
    /// The state in the URL of the page that set the cookie.
    #[serde(rename = "cur")]
    current: Option<String>,
    /// The state the page's language links carry.
    #[serde(rename = "ren")]
    rendered: String,
}

/// A page whose language links open the detached info page, with the
/// cookie that lets it show the same message there.
pub(super) fn detached(
    s: &OidcState,
    realm: &str,
    locale: &PageLocale,
    notice: &Notice,
) -> Response {
    detached_page(s, realm, locale, notice, None, None)
}

/// As `detached`, under a formatted heading, which the detached info page
/// does not keep, as the reference's state cookie does not.
pub(super) fn detached_with_heading(
    s: &OidcState,
    realm: &str,
    locale: &PageLocale,
    notice: &Notice,
    heading: Option<String>,
) -> Response {
    detached_page(s, realm, locale, notice, heading, None)
}

/// As `detached`; `current` is the state in this page's URL, when it is
/// the detached info page itself.
fn detached_page(
    s: &OidcState,
    realm: &str,
    locale: &PageLocale,
    notice: &Notice,
    heading: Option<String>,
    current: Option<&str>,
) -> Response {
    let rendered = random_token();
    let state = DetachedState {
        notice: notice.clone(),
        current: current.map(str::to_owned),
        rendered: rendered.clone(),
    };
    let Ok(json) = serde_json::to_vec(&state) else {
        return unavailable();
    };
    let payload = URL_SAFE_NO_PAD.encode(json);
    let sealed = format!("{payload}.{}", s.signer.seal_state(payload.as_bytes()));
    let switch = format!(
        "{}/realms/{realm}/login-actions/detached-info?kc_state_checker={rendered}&kc_locale=",
        s.path_prefix
    );
    let extras = Extras {
        heading,
        ..Extras::default()
    };
    let mut response = attached(realm, locale, notice, &extras, switch);
    let cookie = format!(
        "{STATE_COOKIE}={sealed}; Path={}/realms/{realm}/; Max-Age={STATE_SECONDS}; Secure; HttpOnly; SameSite=Strict",
        s.path_prefix
    );
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            response.headers_mut().append(header::SET_COOKIE, value);
            response
        }
        Err(_) => unavailable(),
    }
}

/// An error page reached outside any login, in the realm's locale for this
/// browser.
pub(super) async fn error_page(
    s: &OidcState,
    realm: &str,
    realm_id: &str,
    headers: &HeaderMap,
    notice: &Notice,
) -> Response {
    match login_locale::realm_page(s, realm_id, headers).await {
        Ok(locale) => detached(s, realm, &locale, notice),
        Err(()) => unavailable(),
    }
}

/// The cookie's state, when its seal holds and `state` names it.
fn verified_state(s: &OidcState, headers: &HeaderMap, state: &str) -> Option<DetachedState> {
    let (payload, tag) = cookie(headers, STATE_COOKIE)?.split_once('.')?;
    if !s.signer.state_is_sealed(payload.as_bytes(), tag) {
        return None;
    }
    let json = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let found: DetachedState = serde_json::from_slice(&json).ok()?;
    (found.rendered == state || found.current.as_deref() == Some(state)).then_some(found)
}

/// The `kc_state_checker` parameter of the detached info page.
#[derive(Deserialize)]
pub(super) struct StateQuery {
    kc_state_checker: Option<String>,
}

/// Shows the message the state cookie holds, in the picked locale.
pub(super) async fn detached_info(
    State(s): State<OidcState>,
    Path(realm): Path<String>,
    Query(state): Query<StateQuery>,
    Query(locale_query): Query<LocaleQuery>,
    headers: HeaderMap,
) -> Response {
    if !valid_realm(&realm) {
        return failure();
    }
    let realm_id = match s.storage.realm_id_by_name(&realm).await {
        Ok(Some(id)) => id,
        Ok(None) => return failure(),
        Err(_) => return unavailable(),
    };
    let current = state
        .kc_state_checker
        .as_deref()
        .filter(|state| !state.is_empty());
    let Some(found) = current.and_then(|current| verified_state(&s, &headers, current)) else {
        let notice = Notice::error(
            StatusCode::BAD_REQUEST,
            "expiredActionTokenNoSessionMessage",
        );
        return error_page(&s, &realm, &realm_id, &headers, &notice).await;
    };
    let Ok((locale, picked)) =
        login_locale::link_page(&s, &realm, &realm_id, None, &locale_query, &headers).await
    else {
        return unavailable();
    };
    let response = detached_page(&s, &realm, &locale, &found.notice, None, current);
    login_locale::with_cookie(response, picked)
}
