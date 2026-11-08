//! The registration page, as the reference's `registration` flow with
//! `RegistrationPage`, `RegistrationUserCreation` and
//! `RegistrationPassword` and the default user profile, following
//! `tests/reference/registration-observations.json`. A passing form makes
//! an enabled user with an unverified email and signs them in.

use std::sync::Arc;

use axum::Form;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use rs_keycloak_authentication::LoginResult;
use rs_keycloak_storage_postgres::{Actor, Collision, NewPassword, NewUser, UserCreation};
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    Frame, OidcState, csrf, digest, escape, failure, field_error, login_locale, login_steps,
    notice, reshow_url, step_page, unavailable, valid_realm,
};
use crate::locale::PageLocale;

/// Characters `UsernameProhibitedCharactersValidator` refuses, besides
/// whitespace and control characters.
const USERNAME_PROHIBITED: &str = "<>&\"'$%!#?§,;:*~/\\|^=[]{}()`";

/// Characters `PersonNameProhibitedCharactersValidator` refuses, besides
/// control characters and vertical whitespace.
const PERSON_NAME_PROHIBITED: &str = "<>&\"$%!#?§;*~/\\|^=[]{}()";

/// The longest value the default user profile takes, in characters.
const MAX_LENGTH: usize = 255;

/// The longest password this server hashes, in bytes.
const MAX_PASSWORD_BYTES: usize = 1024;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegistrationForm {
    #[serde(default)]
    username: String,
    #[serde(default)]
    email: String,
    #[serde(default, rename = "firstName")]
    first_name: String,
    #[serde(default, rename = "lastName")]
    last_name: String,
    #[serde(default)]
    password: String,
    #[serde(default, rename = "password-confirm")]
    password_confirm: String,
}

/// One field's message: its key and arguments.
struct FieldError {
    field: &'static str,
    key: &'static str,
    args: Vec<String>,
}

impl FieldError {
    fn new(field: &'static str, key: &'static str) -> Self {
        Self {
            field,
            key,
            args: Vec::new(),
        }
    }

    /// `error-invalid-length` and its variants name the field, then the
    /// bounds.
    fn length(field: &'static str, key: &'static str, min: &str) -> Self {
        Self {
            field,
            key,
            args: vec![field.to_owned(), min.to_owned(), MAX_LENGTH.to_string()],
        }
    }
}

/// A live login's realm, client and CSRF token, after the binding checks.
struct Bound {
    realm_id: String,
    client_id: String,
    csrf: String,
    email_as_username: bool,
}

/// Checks the request's login binding and that the realm allows
/// registration; otherwise answers with the reference's error page.
async fn bind(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    headers: &HeaderMap,
) -> Result<Bound, Box<Response>> {
    if !valid_realm(realm) || request_id.len() != 64 {
        return Err(Box::new(failure()));
    }
    let Some(csrf) = csrf(headers).filter(|csrf| csrf.len() == 64) else {
        return Err(Box::new(failure()));
    };
    let (realm_id, client_id) = match s
        .storage
        .authorization_request_client(request_id, &digest(csrf))
        .await
    {
        Ok(Some(binding)) => binding,
        Ok(None) => return Err(Box::new(failure())),
        Err(_) => return Err(Box::new(unavailable())),
    };
    let record = match s.storage.realm_by_name(realm).await {
        Ok(Some(record)) if record.id == realm_id => record,
        Ok(_) => return Err(Box::new(failure())),
        Err(_) => return Err(Box::new(unavailable())),
    };
    if !record.login.registration_allowed {
        let notice =
            notice::Notice::error(StatusCode::BAD_REQUEST, "registrationNotAllowedMessage");
        return Err(Box::new(
            notice::error_page(s, realm, &realm_id, headers, &notice).await,
        ));
    }
    Ok(Bound {
        realm_id,
        client_id,
        csrf: csrf.to_owned(),
        email_as_username: record.user_settings.registration_email_as_username,
    })
}

/// The registration link the login page shows.
pub(super) fn link(
    path_prefix: &str,
    realm: &str,
    request_id: &str,
    locale: &PageLocale,
) -> String {
    let texts = &locale.messages;
    format!(
        "<div id=\"kc-registration\"><span>{} <a href=\"{}/realms/{realm}/login-actions/registration/{request_id}\">{}</a></span></div>",
        texts.html("noAccount", &[]),
        escape(path_prefix),
        texts.html("doRegister", &[]),
    )
}

/// The form with the profile fields in the user profile's order and the
/// password fields after the username, or after the email when it is the
/// username. Password fields are never filled.
fn page(
    s: &OidcState,
    realm: &str,
    request_id: &str,
    bound: &Bound,
    locale: &PageLocale,
    form: &RegistrationForm,
    errors: &[FieldError],
) -> Response {
    let texts = &locale.messages;
    let field = |name: &str, label: &str, kind: &str, value: &str| {
        let messages: Vec<String> = errors
            .iter()
            .filter(|error| error.field == name)
            .map(|error| {
                let args: Vec<&str> = error.args.iter().map(String::as_str).collect();
                texts.html(error.key, &args)
            })
            .collect();
        let error = if messages.is_empty() {
            String::new()
        } else {
            field_error(name, &messages.join(" "))
        };
        format!(
            "<label for=\"{name}\">{}</label><input id=\"{name}\" name=\"{name}\" type=\"{kind}\" value=\"{}\">{error}",
            texts.html(label, &[]),
            escape(value)
        )
    };
    let passwords = format!(
        "{}{}",
        field("password", "password", "password", ""),
        field("password-confirm", "passwordConfirm", "password", "")
    );
    let email = field("email", "email", "email", &form.email);
    let leading = if bound.email_as_username {
        format!("{email}{passwords}")
    } else {
        format!(
            "{}{passwords}{email}",
            field("username", "username", "text", &form.username)
        )
    };
    let prefix = escape(&s.path_prefix);
    let body = format!(
        "<form id=\"kc-register-form\" method=\"post\" action=\"{prefix}/realms/{realm}/login-actions/registration/{request_id}\">{leading}{first}{last}<button id=\"kc-register\" name=\"register\">{submit}</button></form><p><a href=\"{prefix}/realms/{realm}/login-actions/authenticate/{request_id}\">{back}</a></p>",
        first = field("firstName", "firstName", "text", &form.first_name),
        last = field("lastName", "lastName", "text", &form.last_name),
        submit = texts.html("doRegister", &[]),
        back = texts.html("backToLogin", &[]),
    );
    let frame = Frame {
        heading: texts.text("registerTitle", &[]),
        switch: reshow_url(&s.path_prefix, realm, request_id),
    };
    step_page(&s.path_prefix, realm, &bound.csrf, locale, &frame, &body)
}

/// Shows an empty registration form.
pub(super) async fn form(
    State(s): State<OidcState>,
    Path((realm, request_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let bound = match bind(&s, &realm, &request_id, &headers).await {
        Ok(bound) => bound,
        Err(response) => return *response,
    };
    let Ok(locale) = login_locale::page(&s, &bound.realm_id, &request_id, &headers).await else {
        return unavailable();
    };
    page(
        &s,
        &realm,
        &request_id,
        &bound,
        &locale,
        &RegistrationForm::default(),
        &[],
    )
}

fn too_long(value: &str) -> bool {
    value.chars().count() > MAX_LENGTH
}

/// The default user profile's checks of a person name.
fn name_errors(field: &'static str, value: &str, errors: &mut Vec<FieldError>) {
    if value.is_empty() {
        errors.push(FieldError::new(field, "error-user-attribute-required"));
        return;
    }
    if too_long(value) {
        errors.push(FieldError::length(
            field,
            "error-invalid-length-too-long",
            "",
        ));
    }
    if value.chars().any(|c| {
        c.is_control()
            || PERSON_NAME_PROHIBITED.contains(c)
            || matches!(c, '\u{0B}' | '\u{2028}' | '\u{2029}')
    }) {
        errors.push(FieldError::new(
            field,
            "error-person-name-invalid-character",
        ));
    }
}

/// The REGISTRATION profile's username checks, before collisions.
fn username_errors(value: &str, errors: &mut Vec<FieldError>) -> bool {
    if value.is_empty() {
        errors.push(FieldError::new("username", "missingUsernameMessage"));
        return false;
    }
    let before = errors.len();
    let length = value.chars().count();
    if !(3..=MAX_LENGTH).contains(&length) {
        errors.push(FieldError::length("username", "error-invalid-length", "3"));
    }
    if value
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || USERNAME_PROHIBITED.contains(c))
    {
        errors.push(FieldError::new(
            "username",
            "error-username-invalid-character",
        ));
    }
    errors.len() == before
}

/// The REGISTRATION profile's email checks, before collisions.
fn email_errors(value: &str, errors: &mut Vec<FieldError>) -> bool {
    if value.is_empty() {
        errors.push(FieldError::new("email", "missingEmailMessage"));
        return false;
    }
    if !crate::mail::valid_email(value) {
        errors.push(FieldError::new("email", "invalidEmailMessage"));
        return false;
    }
    if too_long(value) {
        errors.push(FieldError::length(
            "email",
            "error-invalid-length-too-long",
            "",
        ));
        return false;
    }
    true
}

/// Checks a submitted form, then makes the user and signs them in.
pub(super) async fn submit(
    State(s): State<OidcState>,
    Path((realm, request_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(mut form): Form<RegistrationForm>,
) -> Response {
    let bound = match bind(&s, &realm, &request_id, &headers).await {
        Ok(bound) => bound,
        Err(response) => return *response,
    };
    let trim = |value: &mut String| *value = value.trim().to_owned();
    trim(&mut form.username);
    trim(&mut form.email);
    trim(&mut form.first_name);
    trim(&mut form.last_name);
    let mut errors = Vec::new();
    // As RegistrationUserCreation: the profile first, each field's format
    // before its collision, then RegistrationPassword.
    let username_valid = !bound.email_as_username && username_errors(&form.username, &mut errors);
    let email_valid = email_errors(&form.email, &mut errors);
    let username = if bound.email_as_username {
        form.email.to_lowercase()
    } else {
        form.username.to_lowercase()
    };
    let email = form.email.to_lowercase();
    if username_valid {
        match s
            .storage
            .new_user_collision(&bound.realm_id, &username, None)
            .await
        {
            Ok(Collision::None) => (),
            Ok(_) => errors.push(FieldError::new("username", "usernameExistsMessage")),
            Err(_) => return unavailable(),
        }
    }
    if email_valid {
        // With the email as username, the username's collision is the
        // email's, as the reference reports it on the email.
        let checked = if bound.email_as_username {
            email.as_str()
        } else {
            ""
        };
        match s
            .storage
            .new_user_collision(&bound.realm_id, checked, Some(&email))
            .await
        {
            Ok(Collision::None) => (),
            Ok(_) => errors.push(FieldError::new("email", "emailExistsMessage")),
            Err(_) => return unavailable(),
        }
    }
    name_errors("firstName", &form.first_name, &mut errors);
    name_errors("lastName", &form.last_name, &mut errors);
    if form.password.is_empty() {
        errors.push(FieldError::new("password", "missingPasswordMessage"));
    } else if form.password != form.password_confirm {
        errors.push(FieldError::new(
            "password-confirm",
            "invalidPasswordConfirmMessage",
        ));
    }
    if form.password.len() > MAX_PASSWORD_BYTES {
        return failure();
    }
    if !errors.is_empty() {
        let Ok(locale) = login_locale::page(&s, &bound.realm_id, &request_id, &headers).await
        else {
            return unavailable();
        };
        return page(&s, &realm, &request_id, &bound, &locale, &form, &errors);
    }
    let password = Zeroizing::new(std::mem::take(&mut form.password));
    let Ok(permit) = Arc::clone(&s.hash_slots).try_acquire_owned() else {
        return unavailable();
    };
    let hashed = {
        let password = password.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            rs_keycloak_crypto::hash_password(password.as_bytes()).map(Zeroizing::new)
        })
        .await
    };
    let Ok(Ok(hash)) = hashed else {
        return unavailable();
    };
    let user_id = Uuid::new_v4().to_string();
    let credential_id = Uuid::new_v4().to_string();
    let user = NewUser {
        username: &username,
        email: Some(&email),
        email_verified: false,
        first_name: Some(&form.first_name),
        last_name: Some(&form.last_name),
        enabled: true,
        required_actions: &[],
    };
    let credential = NewPassword {
        credential_id: &credential_id,
        phc: hash.as_bytes(),
        temporary: false,
    };
    // The new user is the actor of their own creation.
    let actor = Actor {
        realm_id: bound.realm_id.clone(),
        user_id: user_id.clone(),
    };
    match s
        .storage
        .create_user(&bound.realm_id, &user_id, &user, Some(&credential), &actor)
        .await
    {
        Ok(UserCreation::Created) => (),
        // Someone took the name or email since the check.
        Ok(_) => return failure(),
        Err(_) => return unavailable(),
    }
    // Signing in with the new password makes the session the rest of the
    // login continues from, as the reference's flow sets the new user.
    let password = Zeroizing::new(password.as_bytes().to_vec());
    match s
        .login
        .authenticate(
            &bound.realm_id,
            &bound.client_id,
            &username,
            password,
            false,
        )
        .await
    {
        Ok(LoginResult::Authenticated { session_id }) => {
            let held = login_steps::Held {
                realm_id: bound.realm_id,
                session_id,
                csrf: bound.csrf,
            };
            login_steps::continue_login(&s, &realm, &request_id, &held, &headers).await
        }
        Ok(_) => failure(),
        Err(_) => unavailable(),
    }
}
