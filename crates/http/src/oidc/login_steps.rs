//! Login steps after the password: OTP code entry, TOTP setup for users with
//! CONFIGURE_TOTP, and a new password for users with UPDATE_PASSWORD.
//!
//! Follows `tests/reference/otp-observations.json` and
//! `tests/reference/update-password-observations.json`: rejected input shows
//! the same form again, and a code step is accepted once. Seeds are sealed
//! with the operator key, bound to their realm and credential.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use rs_keycloak_protocols::totp;
use rs_keycloak_storage_postgres::{
    AccountChange, LoginStep, Profile, ProfileUpdate, UserSettings,
};
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::consent::escape;
use super::login_locale::{self, LocaleQuery};
use super::{
    OidcState, Rejection, complete_login, csrf, digest, failure, step_page, unavailable,
    valid_realm,
};
use crate::locale::PageLocale;

/// Length of a generated setup secret, as in the reference.
const SECRET_LENGTH: usize = 20;

/// Associated data that binds a sealed seed to one credential.
fn seed_context(realm_id: &str, credential_id: &str) -> Vec<u8> {
    [
        b"otp-seed\0",
        realm_id.as_bytes(),
        b"\0",
        credential_id.as_bytes(),
    ]
    .concat()
}

/// Generates an alphanumeric secret from OS randomness by rejection sampling.
fn new_secret() -> Zeroizing<String> {
    const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut secret = Zeroizing::new(String::with_capacity(SECRET_LENGTH));
    while secret.len() < SECRET_LENGTH {
        for byte in Uuid::new_v4().into_bytes() {
            // 248 is the largest multiple of 62 below 256, so each kept byte is uniform.
            if byte < 248 && secret.len() < SECRET_LENGTH {
                secret.push(char::from(ALPHABET[usize::from(byte % 62)]));
            }
        }
    }
    secret
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |now| now.as_secs())
}

fn setup_page(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    csrf: &str,
    locale: &PageLocale,
    secret: &str,
    error: bool,
) -> Response {
    let prefix = escape(&s.path_prefix);
    let uri = format!(
        "otpauth://totp/{realm}?secret={}&digits={}&algorithm=SHA1&issuer={realm}&period={}",
        totp::base32(secret.as_bytes()),
        totp::DIGITS,
        totp::PERIOD,
    );
    let message = if error {
        "<p role=\"alert\">Invalid authenticator code.</p>"
    } else {
        ""
    };
    let body = format!(
        "<h1>Set up an authenticator</h1>{message}<p>Add this key to your authenticator app: <code>{key}</code></p><p><code>{uri}</code></p><form id=\"kc-totp-settings-form\" method=\"post\" action=\"{prefix}/realms/{realm}/login-actions/totp-setup/{request_id}\"><label>One-time code <input name=\"totp\" type=\"text\" autocomplete=\"one-time-code\" required></label><input type=\"hidden\" name=\"totpSecret\" value=\"{secret}\"><label>Device name <input name=\"userLabel\" type=\"text\"></label><label><input name=\"logout-sessions\" type=\"checkbox\"> Sign out other devices</label><button>Submit</button></form>",
        key = totp::base32(secret.as_bytes()),
        uri = escape(&uri),
        secret = escape(secret),
    );
    step_page(
        &s.path_prefix,
        realm,
        csrf,
        locale,
        "Set up an authenticator",
        &body,
    )
}

fn code_page(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    csrf: &str,
    locale: &PageLocale,
    credential_id: &str,
    error: bool,
) -> Response {
    let prefix = escape(&s.path_prefix);
    let message = if error {
        "<p role=\"alert\">Invalid authenticator code.</p>"
    } else {
        ""
    };
    let body = format!(
        "<h1>Enter your one-time code</h1>{message}<form id=\"kc-otp-login-form\" method=\"post\" action=\"{prefix}/realms/{realm}/login-actions/otp/{request_id}\"><input type=\"hidden\" name=\"selectedCredentialId\" value=\"{credential}\"><label>One-time code <input name=\"otp\" type=\"text\" autocomplete=\"one-time-code\" required></label><button>Sign in</button></form>",
        credential = escape(credential_id),
    );
    step_page(
        &s.path_prefix,
        realm,
        csrf,
        locale,
        "Enter your one-time code",
        &body,
    )
}

/// Holds a password-authenticated request for its next step.
async fn hold(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    held: &Held,
    step: &LoginStep,
    headers: &HeaderMap,
) -> Response {
    let csrf = held.csrf.as_str();
    match s
        .storage
        .attach_pending_session(request_id, &digest(csrf), &held.session_id)
        .await
    {
        Ok(Some(_)) => (),
        Ok(None) => return failure(),
        Err(_) => return unavailable(),
    }
    // Attached, the session's user now counts for the page locale.
    let locale = match login_locale::page(s, &held.realm_id, request_id, headers).await {
        Ok(locale) => locale,
        Err(()) => return unavailable(),
    };
    match step {
        LoginStep::ConfigureTotp => {
            setup_page(s, realm, request_id, csrf, &locale, &new_secret(), false)
        }
        LoginStep::UpdatePassword => password_page(s, realm, request_id, csrf, &locale, false),
        LoginStep::UpdateProfile { username, profile } => {
            let shown = Shown {
                username,
                profile,
                errors: &[],
            };
            match s.storage.user_settings(&held.realm_id).await {
                Ok(settings) => {
                    profile_page(s, realm, request_id, csrf, &locale, &settings, &shown)
                }
                Err(_) => unavailable(),
            }
        }
        LoginStep::VerifyEmail { user_id, email } => {
            verify_email_page(s, realm, request_id, csrf, &locale, user_id, email).await
        }
        LoginStep::VerifyTotp(credential) => {
            code_page(s, realm, request_id, csrf, &locale, &credential.id, false)
        }
        LoginStep::Complete => failure(),
    }
}

/// The session held on a request, with its realm, after the CSRF check.
pub(super) struct Held {
    /// The request's realm.
    pub(super) realm_id: String,
    /// The password-authenticated session.
    pub(super) session_id: String,
    /// The request's CSRF cookie.
    pub(super) csrf: String,
}

/// The locale of a page re-shown for the held session.
async fn shown_locale(
    s: &OidcState,
    held: &Held,
    request_id: &str,
    headers: &HeaderMap,
) -> Result<PageLocale, ()> {
    login_locale::page(s, &held.realm_id, request_id, headers).await
}

async fn held(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    headers: &HeaderMap,
) -> Result<Held, Rejection> {
    if !valid_realm(realm) || request_id.len() != 64 {
        return Err(Rejection::Invalid);
    }
    let Some(csrf) = csrf(headers).filter(|csrf| csrf.len() == 64) else {
        return Err(Rejection::Invalid);
    };
    let pending = match s.storage.pending_request(request_id, &digest(csrf)).await {
        Ok(Some(pending)) => pending,
        Ok(None) => return Err(Rejection::Invalid),
        Err(_) => return Err(Rejection::Unavailable),
    };
    let realm_id = match s.storage.realm_id_by_name(realm).await {
        Ok(Some(id)) => id,
        Ok(None) => return Err(Rejection::Invalid),
        Err(_) => return Err(Rejection::Unavailable),
    };
    Ok(Held {
        realm_id,
        session_id: pending.session_id,
        csrf: csrf.to_owned(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CodeForm {
    otp: String,
    #[serde(rename = "selectedCredentialId")]
    _selected_credential_id: Option<String>,
}

/// Takes a step's `kc_locale` pick, then runs the step; the pick's cookie
/// goes with the step's response.
async fn with_pick<F>(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    query: &LocaleQuery,
    held: &Held,
    step: F,
) -> Response
where
    F: Future<Output = Response>,
{
    match login_locale::pick(s, realm, &held.realm_id, request_id, query).await {
        Ok(picked) => login_locale::with_cookie(step.await, picked),
        Err(()) => unavailable(),
    }
}

/// Checks an entered code for a user with an OTP credential.
pub(super) async fn verify(
    State(s): State<OidcState>,
    Path((realm, request_id)): Path<(String, String)>,
    Query(query): Query<LocaleQuery>,
    headers: HeaderMap,
    Form(form): Form<CodeForm>,
) -> Response {
    let held = match held(&s, &realm, &request_id, &headers).await {
        Ok(held) => held,
        Err(rejected) => return rejected.into_response(),
    };
    let step = verify_code(&s, &realm, &request_id, &held, &headers, form);
    with_pick(&s, &realm, &request_id, &query, &held, step).await
}

async fn verify_code(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    held: &Held,
    headers: &HeaderMap,
    form: CodeForm,
) -> Response {
    let credential = match s.storage.login_step(&held.realm_id, &held.session_id).await {
        Ok(LoginStep::VerifyTotp(credential)) => credential,
        Ok(_) => return failure(),
        Err(_) => return unavailable(),
    };
    let Some(key) = s
        .secret_key
        .as_ref()
        .filter(|key| key.key_id() == credential.key_id)
    else {
        return unavailable();
    };
    let Ok(seed) = key.open(
        &credential.sealed,
        &seed_context(&held.realm_id, &credential.id),
    ) else {
        return unavailable();
    };
    let last_step = credential
        .last_step
        .and_then(|step| u64::try_from(step).ok());
    let accepted = match totp::verify(&seed, form.otp.trim(), now(), last_step) {
        Some(step) => match i64::try_from(step) {
            Ok(step) => {
                s.storage
                    .accept_otp(&held.realm_id, &held.session_id, &credential.id, step)
                    .await
            }
            Err(_) => return failure(),
        },
        None => Ok(false),
    };
    match accepted {
        Ok(true) => continue_login(s, realm, request_id, held, headers).await,
        Ok(false) => match shown_locale(s, held, request_id, headers).await {
            Ok(locale) => code_page(
                s,
                realm,
                request_id,
                &held.csrf,
                &locale,
                &credential.id,
                true,
            ),
            Err(()) => unavailable(),
        },
        Err(_) => unavailable(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SetupForm {
    totp: String,
    #[serde(rename = "totpSecret")]
    totp_secret: String,
    #[serde(rename = "userLabel")]
    user_label: Option<String>,
    #[serde(rename = "logout-sessions")]
    logout_sessions: Option<String>,
}

/// Ends the user's other sessions when the form's checkbox was set.
async fn logout_others(s: &OidcState, held: &Held, checkbox: Option<&str>) -> Result<(), ()> {
    if checkbox == Some("on") {
        s.storage
            .end_other_sessions(&held.realm_id, &held.session_id, false)
            .await
            .map_err(|_| ())?;
    }
    Ok(())
}

/// Completes TOTP setup when the entered code matches the shown secret.
pub(super) async fn configure(
    State(s): State<OidcState>,
    Path((realm, request_id)): Path<(String, String)>,
    Query(query): Query<LocaleQuery>,
    headers: HeaderMap,
    Form(form): Form<SetupForm>,
) -> Response {
    let held = match held(&s, &realm, &request_id, &headers).await {
        Ok(held) => held,
        Err(rejected) => return rejected.into_response(),
    };
    let step = set_up_totp(&s, &realm, &request_id, &held, &headers, form);
    with_pick(&s, &realm, &request_id, &query, &held, step).await
}

async fn set_up_totp(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    held: &Held,
    headers: &HeaderMap,
    form: SetupForm,
) -> Response {
    match s.storage.login_step(&held.realm_id, &held.session_id).await {
        Ok(LoginStep::ConfigureTotp) => (),
        Ok(_) => return failure(),
        Err(_) => return unavailable(),
    }
    let secret = Zeroizing::new(form.totp_secret);
    if secret.len() != SECRET_LENGTH || !secret.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return failure();
    }
    let Some(step) = totp::verify(secret.as_bytes(), form.totp.trim(), now(), None)
        .and_then(|step| i64::try_from(step).ok())
    else {
        return match shown_locale(s, held, request_id, headers).await {
            Ok(locale) => setup_page(s, realm, request_id, &held.csrf, &locale, &secret, true),
            Err(()) => unavailable(),
        };
    };
    let Some(key) = s.secret_key.as_ref() else {
        return unavailable();
    };
    let credential_id = Uuid::new_v4().to_string();
    let Ok(sealed) = key.seal(
        secret.as_bytes(),
        &seed_context(&held.realm_id, &credential_id),
    ) else {
        return unavailable();
    };
    let label = form
        .user_label
        .as_deref()
        .map(str::trim)
        .filter(|label| !label.is_empty() && label.len() <= 255);
    match s
        .storage
        .configure_otp(
            &held.realm_id,
            &held.session_id,
            &credential_id,
            &sealed,
            key.key_id(),
            label,
            step,
        )
        .await
    {
        Ok(true) => {
            if logout_others(s, held, form.logout_sessions.as_deref())
                .await
                .is_err()
            {
                return unavailable();
            }
            continue_login(s, realm, request_id, held, headers).await
        }
        Ok(false) => failure(),
        Err(_) => unavailable(),
    }
}

/// Applies the user's locale, then shows the session's next login step, or
/// finishes the login when none is left. Every step handler continues
/// through here, as the reference evaluates its locale required action
/// whenever required actions are.
pub(super) async fn continue_login(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    held: &Held,
    headers: &HeaderMap,
) -> Response {
    let cookie = match login_locale::adopt(
        s,
        realm,
        &held.realm_id,
        request_id,
        &held.session_id,
        headers,
    )
    .await
    {
        Ok(cookie) => cookie,
        Err(()) => return unavailable(),
    };
    let response = match s.storage.login_step(&held.realm_id, &held.session_id).await {
        Ok(LoginStep::Complete) => complete_login(s, realm, request_id, held, headers).await,
        Ok(step) => hold(s, realm, request_id, held, &step, headers).await,
        Err(_) => unavailable(),
    };
    login_locale::with_cookie(response, cookie)
}

fn password_page(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    csrf: &str,
    locale: &PageLocale,
    error: bool,
) -> Response {
    let prefix = escape(&s.path_prefix);
    let message = if error {
        "<p role=\"alert\">Passwords must match and must not be empty.</p>"
    } else {
        ""
    };
    let body = format!(
        "<h1>Update your password</h1>{message}<form id=\"kc-passwd-update-form\" method=\"post\" action=\"{prefix}/realms/{realm}/login-actions/update-password/{request_id}\"><label>New password <input name=\"password-new\" type=\"password\" autocomplete=\"new-password\" required></label><label>Confirm password <input name=\"password-confirm\" type=\"password\" autocomplete=\"new-password\" required></label><label><input name=\"logout-sessions\" type=\"checkbox\"> Sign out other devices</label><button>Submit</button></form>"
    );
    step_page(
        &s.path_prefix,
        realm,
        csrf,
        locale,
        "Update your password",
        &body,
    )
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

/// Longest password the login path accepts.
const MAX_PASSWORD_BYTES: usize = 1024;

/// Replaces the password of a user with UPDATE_PASSWORD.
pub(super) async fn update_password(
    State(s): State<OidcState>,
    Path((realm, request_id)): Path<(String, String)>,
    Query(query): Query<LocaleQuery>,
    headers: HeaderMap,
    Form(form): Form<PasswordForm>,
) -> Response {
    let held = match held(&s, &realm, &request_id, &headers).await {
        Ok(held) => held,
        Err(rejected) => return rejected.into_response(),
    };
    let step = replace_password(&s, &realm, &request_id, &held, &headers, form);
    with_pick(&s, &realm, &request_id, &query, &held, step).await
}

async fn replace_password(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    held: &Held,
    headers: &HeaderMap,
    form: PasswordForm,
) -> Response {
    match s.storage.login_step(&held.realm_id, &held.session_id).await {
        Ok(LoginStep::UpdatePassword) => (),
        Ok(_) => return failure(),
        Err(_) => return unavailable(),
    }
    let password = Zeroizing::new(form.password_new);
    let confirm = Zeroizing::new(form.password_confirm);
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES || *password != *confirm {
        return match shown_locale(s, held, request_id, headers).await {
            Ok(locale) => password_page(s, realm, request_id, &held.csrf, &locale, true),
            Err(()) => unavailable(),
        };
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
    match s
        .storage
        .update_password_step(
            &held.realm_id,
            &held.session_id,
            &Uuid::new_v4().to_string(),
            hash.as_bytes(),
        )
        .await
    {
        Ok(true) => {
            if logout_others(s, held, form.logout_sessions.as_deref())
                .await
                .is_err()
            {
                return unavailable();
            }
            continue_login(s, realm, request_id, held, headers).await
        }
        Ok(false) => failure(),
        Err(_) => unavailable(),
    }
}

/// Lifespan of a link sent during login, as Keycloak's default (5 minutes).
const LOGIN_LINK_SECONDS: i32 = 300;

/// Sends a verification link bound to this login request, then shows the
/// waiting page with a resend link.
async fn verify_email_page(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    csrf: &str,
    locale: &PageLocale,
    user_id: &str,
    email: &str,
) -> Response {
    let record = match s.storage.realm_by_name(realm).await {
        Ok(Some(record)) => record,
        Ok(None) => return failure(),
        Err(_) => return unavailable(),
    };
    if let Some(settings) = crate::mail::settings(&record) {
        let key = Zeroizing::new(super::random_token());
        let actions = ["VERIFY_EMAIL".to_owned()];
        match s
            .storage
            .issue_action_token(
                &record.id,
                user_id,
                &digest(&key),
                &actions,
                LOGIN_LINK_SECONDS,
                Some(request_id),
            )
            .await
        {
            Ok(true) => {
                let link = crate::mail::action_link(s, realm, &key);
                // A failed send still shows the page; the user can resend.
                let _ = crate::mail::send_verification(
                    &settings,
                    realm,
                    email,
                    &link,
                    LOGIN_LINK_SECONDS,
                )
                .await;
            }
            Ok(false) => return failure(),
            Err(_) => return unavailable(),
        }
    }
    let body = format!(
        "<h1>Email verification</h1><p>You need to verify your email address to activate your account.</p><p>An email with instructions to verify your email address has been sent to your address {email}.</p><p>Haven't received a verification code in your email? <a href=\"{prefix}/realms/{realm}/login-actions/required-action?request={request_id}&amp;execution=VERIFY_EMAIL\">Click here</a> to re-send the email.</p>",
        email = escape(email),
        prefix = escape(&s.path_prefix),
    );
    step_page(
        &s.path_prefix,
        realm,
        csrf,
        locale,
        "Email verification",
        &body,
    )
}

/// Re-sends the verification email for a login waiting on it.
pub(super) async fn resend(
    State(s): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<std::collections::BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let Some(request_id) = params.get("request") else {
        return failure();
    };
    let held = match held(&s, &realm, request_id, &headers).await {
        Ok(held) => held,
        Err(rejection) => return rejection.into_response(),
    };
    match s.storage.login_step(&held.realm_id, &held.session_id).await {
        Ok(LoginStep::VerifyEmail { user_id, email }) => {
            match shown_locale(&s, &held, request_id, &headers).await {
                Ok(locale) => {
                    verify_email_page(
                        &s, &realm, request_id, &held.csrf, &locale, &user_id, &email,
                    )
                    .await
                }
                Err(()) => unavailable(),
            }
        }
        Ok(_) => failure(),
        Err(_) => unavailable(),
    }
}

/// Whether the profile form shows the username, as the pinned profile's
/// read condition for UPDATE_PROFILE: when usernames may change and the
/// email is not the username.
fn username_shown(settings: &UserSettings) -> bool {
    settings.edit_username_allowed && !settings.registration_email_as_username
}

/// Whether the profile form shows the email: unless it is the username and
/// usernames may not change.
fn email_shown(settings: &UserSettings) -> bool {
    !settings.registration_email_as_username || settings.edit_username_allowed
}

/// What the profile form shows: values, and each field's messages in
/// order.
struct Shown<'a> {
    username: &'a str,
    profile: &'a Profile,
    errors: &'a [(&'a str, &'a str)],
}

/// Shows the profile form with the realm's fields, the given values and
/// any field messages.
fn profile_page(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    csrf: &str,
    locale: &PageLocale,
    settings: &UserSettings,
    shown: &Shown<'_>,
) -> Response {
    let field = |name: &str, label: &str, value: Option<&str>, kind: &str| {
        let messages: Vec<String> = shown
            .errors
            .iter()
            .filter(|(field, _)| *field == name)
            .map(|(_, message)| escape(message))
            .collect();
        let error = if messages.is_empty() {
            String::new()
        } else {
            format!(
                "<span id=\"input-error-{name}\" role=\"alert\">{}</span>",
                messages.join("<br>")
            )
        };
        format!(
            "<label>{label} <input name=\"{name}\" type=\"{kind}\" value=\"{}\" required></label>{error}",
            escape(value.unwrap_or_default())
        )
    };
    let profile = shown.profile;
    let username = if username_shown(settings) {
        field("username", "Username", Some(shown.username), "text")
    } else {
        String::new()
    };
    let email = if email_shown(settings) {
        field("email", "Email", profile.email.as_deref(), "email")
    } else {
        String::new()
    };
    let body = format!(
        "<h1>Update account information</h1><form id=\"kc-update-profile-form\" method=\"post\" action=\"{prefix}/realms/{realm}/login-actions/update-profile/{request_id}\">{username}{email}{first}{last}<button>Submit</button></form>",
        prefix = escape(&s.path_prefix),
        first = field(
            "firstName",
            "First name",
            profile.first_name.as_deref(),
            "text"
        ),
        last = field(
            "lastName",
            "Last name",
            profile.last_name.as_deref(),
            "text"
        ),
    );
    step_page(
        &s.path_prefix,
        realm,
        csrf,
        locale,
        "Update account information",
        &body,
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProfileForm {
    username: Option<String>,
    email: Option<String>,
    #[serde(rename = "firstName")]
    first_name: String,
    #[serde(rename = "lastName")]
    last_name: String,
}

/// Saves the profile of a user with UPDATE_PROFILE.
pub(super) async fn update_profile(
    State(s): State<OidcState>,
    Path((realm, request_id)): Path<(String, String)>,
    Query(query): Query<LocaleQuery>,
    headers: HeaderMap,
    Form(form): Form<ProfileForm>,
) -> Response {
    let held = match held(&s, &realm, &request_id, &headers).await {
        Ok(held) => held,
        Err(rejection) => return rejection.into_response(),
    };
    let step = save_profile(&s, &realm, &request_id, &held, &headers, form);
    with_pick(&s, &realm, &request_id, &query, &held, step).await
}

/// Checks and saves a submitted profile under the realm's username rules,
/// as the pinned user profile does for UPDATE_PROFILE and
/// `tests/reference/login-settings-observations.json` records: a username
/// the form does not show must not change, a shown one may, and when the
/// email is the username the username follows the email.
async fn save_profile(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    held: &Held,
    headers: &HeaderMap,
    form: ProfileForm,
) -> Response {
    let (current, stored) = match s.storage.login_step(&held.realm_id, &held.session_id).await {
        Ok(LoginStep::UpdateProfile { username, profile }) => (username, profile),
        Ok(_) => return failure(),
        Err(_) => return unavailable(),
    };
    let settings = match s.storage.user_settings(&held.realm_id).await {
        Ok(settings) => settings,
        Err(_) => return unavailable(),
    };
    let text = |value: &str| {
        Some(value.trim().to_owned()).filter(|value| !value.is_empty() && value.len() <= 255)
    };
    // Fields the form does not show keep their stored values.
    let email = if email_shown(&settings) {
        form.email.as_deref().and_then(text)
    } else {
        stored.email.clone()
    };
    let profile = Profile {
        first_name: text(&form.first_name),
        last_name: text(&form.last_name),
        email,
    };
    let mut errors = Vec::new();
    // A changed username the form does not show is refused without a
    // message, since the reference reports it on the hidden field.
    let mut hidden_error = false;
    let submitted = form.username.as_deref().map(str::trim).unwrap_or_default();
    let username = if settings.registration_email_as_username {
        profile.email.clone().unwrap_or_default()
    } else if username_shown(&settings) {
        if submitted.is_empty() {
            errors.push(("username", "Please specify username."));
            current.clone()
        } else {
            submitted.to_owned()
        }
    } else {
        hidden_error = form
            .username
            .as_deref()
            .is_some_and(|username| username.trim().to_lowercase() != current);
        current.clone()
    };
    if email_shown(&settings)
        && profile
            .email
            .as_deref()
            .is_none_or(|email| !crate::mail::valid_email(email))
    {
        errors.push(("email", "Invalid email address."));
    }
    if profile.first_name.is_none() {
        errors.push(("firstName", "Please specify first name."));
    }
    if profile.last_name.is_none() {
        errors.push(("lastName", "Please specify last name."));
    }
    let change = AccountChange {
        checked_username: &username,
        saved_username: &username,
        profile: profile.clone(),
        locale: None,
        email_as_username: settings.registration_email_as_username,
    };
    let apply = errors.is_empty() && !hidden_error;
    let conflicts = match s
        .storage
        .update_profile_step(&held.realm_id, &held.session_id, &change, apply)
        .await
    {
        Ok(ProfileUpdate::Updated) => {
            return continue_login(s, realm, request_id, held, headers).await;
        }
        Ok(ProfileUpdate::Checked(conflicts)) => conflicts,
        Ok(ProfileUpdate::NotPending) => return failure(),
        Err(_) => return unavailable(),
    };
    // Each field lists its format error before its collisions.
    if conflicts.username_taken || conflicts.username_is_email {
        errors.push(("username", "Username already exists."));
    }
    if conflicts.email_taken || conflicts.email_is_username {
        errors.push((
            "email",
            "This email is already associated with an existing account.",
        ));
    }
    if conflicts.email_as_username {
        errors.push(("email", "Username already exists."));
    }
    let Ok(locale) = shown_locale(s, held, request_id, headers).await else {
        return unavailable();
    };
    let shown_email = Profile {
        email: form.email.as_deref().map(|email| email.trim().to_owned()),
        ..profile
    };
    let shown = Shown {
        username: submitted,
        profile: &shown_email,
        errors: &errors,
    };
    profile_page(s, realm, request_id, &held.csrf, &locale, &settings, &shown)
}
