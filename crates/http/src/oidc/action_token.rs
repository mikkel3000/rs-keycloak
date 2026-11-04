//! Links sent by email: `/login-actions/action-token?key=`.
//!
//! Follows `tests/reference/execute-actions-observations.json`: the link
//! opens an info page, then the password form, then a confirmation; a used
//! or expired key answers 400. Keys are single use and stored as digests.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Form, Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use rs_keycloak_storage_postgres::ActionToken;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::consent::escape;
use super::{OidcState, digest, plain_page, unavailable, valid_realm};

/// Longest password the login path accepts.
const MAX_PASSWORD_BYTES: usize = 1024;

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

fn password_form(s: &OidcState, realm: &str, key: &str, error: bool) -> Response {
    let message = if error {
        "<p role=\"alert\">Passwords must match and must not be empty.</p>"
    } else {
        ""
    };
    let body = format!(
        "<h1>Update your password</h1>{message}<form id=\"kc-passwd-update-form\" method=\"post\" action=\"{action}\"><label>New password <input name=\"password-new\" type=\"password\" autocomplete=\"new-password\" required></label><label>Confirm password <input name=\"password-confirm\" type=\"password\" autocomplete=\"new-password\" required></label><label><input name=\"logout-sessions\" type=\"checkbox\"> Sign out other devices</label><button>Submit</button></form>",
        action = link(s, realm, key),
    );
    plain_page(StatusCode::OK, "Update your password", &body)
}

/// Shows the info page, or the password form once the user proceeds.
pub(super) async fn show(
    State(s): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    let key = params.get("key").map(String::as_str);
    if let Err(refused) = live(&s, &realm, key).await {
        return refused.into_response();
    }
    let key = key.unwrap_or_default();
    if params.get("execute").map(String::as_str) == Some("UPDATE_PASSWORD") {
        return password_form(&s, &realm, key, false);
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
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES || *password != *confirm {
        return password_form(&s, &realm, key, true);
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
        .redeem_password_token(
            &realm_id,
            &digest(key),
            &Uuid::new_v4().to_string(),
            hash.as_bytes(),
        )
        .await
    {
        Ok(true) => (),
        Ok(false) => return expired(),
        Err(_) => return unavailable(),
    }
    if form.logout_sessions.as_deref() == Some("on")
        && s.storage
            .end_user_sessions(&realm_id, &token.user_id)
            .await
            .is_err()
    {
        return unavailable();
    }
    plain_page(
        StatusCode::OK,
        "Account updated",
        "<p>Your account has been updated.</p>",
    )
}
