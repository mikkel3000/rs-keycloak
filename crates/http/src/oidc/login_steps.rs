//! Login steps after the password: OTP code entry, TOTP setup for users with
//! CONFIGURE_TOTP, and a new password for users with UPDATE_PASSWORD.
//!
//! Follows `tests/reference/otp-observations.json` and
//! `tests/reference/update-password-observations.json`: rejected input shows
//! the same form again, and a code step is accepted once. Seeds are sealed
//! with the operator key, bound to their realm and credential.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use rs_keycloak_protocols::totp;
use rs_keycloak_storage_postgres::LoginStep;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::consent::escape;
use super::{
    OidcState, complete_login, csrf, digest, failure, step_page, unavailable, valid_realm,
};

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
        "Set up an authenticator",
        &body,
    )
}

fn code_page(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    csrf: &str,
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
        "Enter your one-time code",
        &body,
    )
}

/// Holds a password-authenticated request for its second factor.
pub(super) async fn hold(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    csrf: &str,
    session_id: &str,
    step: &LoginStep,
) -> Response {
    match s
        .storage
        .attach_pending_session(request_id, &digest(csrf), session_id)
        .await
    {
        Ok(Some(_)) => (),
        Ok(None) => return failure(),
        Err(_) => return unavailable(),
    }
    match step {
        LoginStep::ConfigureTotp => setup_page(s, realm, request_id, csrf, &new_secret(), false),
        LoginStep::UpdatePassword => password_page(s, realm, request_id, csrf, false),
        LoginStep::VerifyTotp(credential) => {
            code_page(s, realm, request_id, csrf, &credential.id, false)
        }
        LoginStep::Complete => failure(),
    }
}

/// The session held on a request, with its realm, after the CSRF check.
struct Held {
    realm_id: String,
    session_id: String,
    csrf: String,
}

/// Why a login-step submission was refused before its form was checked.
enum Rejected {
    Invalid,
    Unavailable,
}

impl Rejected {
    fn into_response(self) -> Response {
        match self {
            Self::Invalid => failure(),
            Self::Unavailable => unavailable(),
        }
    }
}

async fn held(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    headers: &HeaderMap,
) -> Result<Held, Rejected> {
    if !valid_realm(realm) || request_id.len() != 64 {
        return Err(Rejected::Invalid);
    }
    let Some(csrf) = csrf(headers).filter(|csrf| csrf.len() == 64) else {
        return Err(Rejected::Invalid);
    };
    let pending = match s.storage.pending_request(request_id, &digest(csrf)).await {
        Ok(Some(pending)) => pending,
        Ok(None) => return Err(Rejected::Invalid),
        Err(_) => return Err(Rejected::Unavailable),
    };
    let realm_id = match s.storage.realm_id_by_name(realm).await {
        Ok(Some(id)) => id,
        Ok(None) => return Err(Rejected::Invalid),
        Err(_) => return Err(Rejected::Unavailable),
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

/// Checks an entered code for a user with an OTP credential.
pub(super) async fn verify(
    State(s): State<OidcState>,
    Path((realm, request_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<CodeForm>,
) -> Response {
    let held = match held(&s, &realm, &request_id, &headers).await {
        Ok(held) => held,
        Err(rejected) => return rejected.into_response(),
    };
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
        Ok(true) => {
            continue_login(
                &s,
                &realm,
                &held.realm_id,
                &request_id,
                &held.csrf,
                &held.session_id,
            )
            .await
        }
        Ok(false) => code_page(&s, &realm, &request_id, &held.csrf, &credential.id, true),
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
    _logout_sessions: Option<String>,
}

/// Completes TOTP setup when the entered code matches the shown secret.
pub(super) async fn configure(
    State(s): State<OidcState>,
    Path((realm, request_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<SetupForm>,
) -> Response {
    let held = match held(&s, &realm, &request_id, &headers).await {
        Ok(held) => held,
        Err(rejected) => return rejected.into_response(),
    };
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
        return setup_page(&s, &realm, &request_id, &held.csrf, &secret, true);
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
            continue_login(
                &s,
                &realm,
                &held.realm_id,
                &request_id,
                &held.csrf,
                &held.session_id,
            )
            .await
        }
        Ok(false) => failure(),
        Err(_) => unavailable(),
    }
}

/// Shows the session's next login step, or finishes the login when none is
/// left. Every step handler continues through here.
pub(super) async fn continue_login(
    s: &OidcState,
    realm: &str,
    realm_id: &str,
    request_id: &str,
    csrf: &str,
    session_id: &str,
) -> Response {
    match s.storage.login_step(realm_id, session_id).await {
        Ok(LoginStep::Complete) => {
            complete_login(s, realm, realm_id, request_id, csrf, session_id).await
        }
        Ok(step) => hold(s, realm, request_id, csrf, session_id, &step).await,
        Err(_) => unavailable(),
    }
}

fn password_page(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    csrf: &str,
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
    step_page(&s.path_prefix, realm, csrf, "Update your password", &body)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PasswordForm {
    #[serde(rename = "password-new")]
    password_new: String,
    #[serde(rename = "password-confirm")]
    password_confirm: String,
    #[serde(rename = "logout-sessions")]
    _logout_sessions: Option<String>,
}

/// Longest password the login path accepts.
const MAX_PASSWORD_BYTES: usize = 1024;

/// Replaces the password of a user with UPDATE_PASSWORD.
pub(super) async fn update_password(
    State(s): State<OidcState>,
    Path((realm, request_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<PasswordForm>,
) -> Response {
    let held = match held(&s, &realm, &request_id, &headers).await {
        Ok(held) => held,
        Err(rejected) => return rejected.into_response(),
    };
    match s.storage.login_step(&held.realm_id, &held.session_id).await {
        Ok(LoginStep::UpdatePassword) => (),
        Ok(_) => return failure(),
        Err(_) => return unavailable(),
    }
    let password = Zeroizing::new(form.password_new);
    let confirm = Zeroizing::new(form.password_confirm);
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES || *password != *confirm {
        return password_page(&s, &realm, &request_id, &held.csrf, true);
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
            continue_login(
                &s,
                &realm,
                &held.realm_id,
                &request_id,
                &held.csrf,
                &held.session_id,
            )
            .await
        }
        Ok(false) => failure(),
        Err(_) => unavailable(),
    }
}
