//! Realm settings of the login flow, kept apart from the realm's core
//! columns: each is read with the realm and changed by one statement in
//! the realm's create or update transaction. A new realm starts from the
//! columns' defaults, which are the reference's.

use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row};

use crate::StorageError;

/// The login-flow settings of a realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginSettings {
    /// Whether the login form offers "Remember me".
    pub remember_me: bool,
    /// Idle timeout of remembered sessions in seconds; 0 or less keeps the
    /// normal one.
    pub sso_session_idle_timeout_remember_me: i32,
    /// Lifespan of remembered sessions in seconds; 0 or less keeps the
    /// normal one.
    pub sso_session_max_lifespan_remember_me: i32,
    /// Whether the login page links to the registration form.
    pub registration_allowed: bool,
}

/// Changes to a realm's login-flow settings; `None` keeps one, or for a
/// new realm its default.
#[derive(Clone, Debug, Default)]
pub struct LoginSettingChanges {
    /// See [`LoginSettings::remember_me`].
    pub remember_me: Option<bool>,
    /// See [`LoginSettings::sso_session_idle_timeout_remember_me`].
    pub sso_session_idle_timeout_remember_me: Option<i32>,
    /// See [`LoginSettings::sso_session_max_lifespan_remember_me`].
    pub sso_session_max_lifespan_remember_me: Option<i32>,
    /// See [`LoginSettings::registration_allowed`].
    pub registration_allowed: Option<bool>,
}

/// The realm columns [`login_settings_row`] reads.
pub(crate) const LOGIN_SETTING_COLUMNS: &str = "remember_me, sso_session_idle_timeout_remember_me, sso_session_max_lifespan_remember_me, registration_allowed";

pub(crate) fn login_settings_row(row: &PgRow) -> Result<LoginSettings, StorageError> {
    Ok(LoginSettings {
        remember_me: row.try_get("remember_me")?,
        sso_session_idle_timeout_remember_me: row
            .try_get("sso_session_idle_timeout_remember_me")?,
        sso_session_max_lifespan_remember_me: row
            .try_get("sso_session_max_lifespan_remember_me")?,
        registration_allowed: row.try_get("registration_allowed")?,
    })
}

/// Applies changes to the realm with this name.
pub(crate) async fn change_login_settings(
    connection: &mut PgConnection,
    realm: &str,
    changes: &LoginSettingChanges,
) -> Result<(), StorageError> {
    sqlx::query("UPDATE realms SET remember_me = COALESCE($2, remember_me), sso_session_idle_timeout_remember_me = COALESCE($3, sso_session_idle_timeout_remember_me), sso_session_max_lifespan_remember_me = COALESCE($4, sso_session_max_lifespan_remember_me), registration_allowed = COALESCE($5, registration_allowed) WHERE name = $1")
        .bind(realm)
        .bind(changes.remember_me)
        .bind(changes.sso_session_idle_timeout_remember_me)
        .bind(changes.sso_session_max_lifespan_remember_me)
        .bind(changes.registration_allowed)
        .execute(connection)
        .await?;
    Ok(())
}
