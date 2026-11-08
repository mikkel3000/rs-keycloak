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
    /// The OTP policy new credentials take.
    pub otp_policy: OtpPolicy,
    /// Brute-force detection on the login form.
    pub brute_force: BruteForce,
}

/// A realm's brute-force detection settings, as the reference's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BruteForce {
    /// Whether failures are counted and users locked.
    pub protected: bool,
    /// Whether enough failures disable the user.
    pub permanent_lockout: bool,
    /// Temporary lockouts before a permanent one; 0 locks permanently at
    /// `failure_factor` failures.
    pub max_temporary_lockouts: i32,
    /// `MULTIPLE` or `LINEAR`, how the wait grows.
    pub strategy: String,
    /// The longest temporary lockout in seconds.
    pub max_failure_wait_seconds: i32,
    /// The lockout after failures closer than `quick_login_check_milli_seconds`.
    pub minimum_quick_login_wait_seconds: i32,
    /// The step the wait grows by in seconds.
    pub wait_increment_seconds: i32,
    /// Failures closer than this in milliseconds count as quick.
    pub quick_login_check_milli_seconds: i64,
    /// Failures further apart than this in seconds start a new count.
    pub max_delta_time_seconds: i32,
    /// Failures per wait increment.
    pub failure_factor: i32,
}

/// Changes to a realm's brute-force settings; `None` keeps one.
#[derive(Clone, Debug, Default)]
pub struct BruteForceChanges {
    /// See [`BruteForce::protected`].
    pub protected: Option<bool>,
    /// See [`BruteForce::permanent_lockout`].
    pub permanent_lockout: Option<bool>,
    /// See [`BruteForce::max_temporary_lockouts`].
    pub max_temporary_lockouts: Option<i32>,
    /// See [`BruteForce::strategy`].
    pub strategy: Option<String>,
    /// See [`BruteForce::max_failure_wait_seconds`].
    pub max_failure_wait_seconds: Option<i32>,
    /// See [`BruteForce::minimum_quick_login_wait_seconds`].
    pub minimum_quick_login_wait_seconds: Option<i32>,
    /// See [`BruteForce::wait_increment_seconds`].
    pub wait_increment_seconds: Option<i32>,
    /// See [`BruteForce::quick_login_check_milli_seconds`].
    pub quick_login_check_milli_seconds: Option<i64>,
    /// See [`BruteForce::max_delta_time_seconds`].
    pub max_delta_time_seconds: Option<i32>,
    /// See [`BruteForce::failure_factor`].
    pub failure_factor: Option<i32>,
}

/// A realm's OTP policy as stored, unchecked as in the reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtpPolicy {
    /// `totp` or `hotp`; other values are kept but make no codes.
    pub kind: String,
    /// Java HMAC name such as `HmacSHA1`, if any.
    pub algorithm: Option<String>,
    /// Digits in a code.
    pub digits: i32,
    /// Seconds per TOTP step.
    pub period: i32,
    /// Steps or counters checked besides the expected one.
    pub look_ahead: i32,
    /// The counter a new HOTP credential starts at.
    pub initial_counter: i32,
    /// Whether a TOTP code may be used again.
    pub code_reusable: bool,
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
    /// A policy that replaces the realm's whole OTP policy.
    pub otp_policy: Option<OtpPolicy>,
    /// Brute-force detection settings.
    pub brute_force: BruteForceChanges,
}

/// The realm columns of brute-force detection, in [`BruteForce`]'s order.
pub(crate) const BRUTE_FORCE_COLUMNS: &str = "brute_force_protected, permanent_lockout, max_temporary_lockouts, brute_force_strategy, max_failure_wait_seconds, minimum_quick_login_wait_seconds, wait_increment_seconds, quick_login_check_milli_seconds, max_delta_time_seconds, failure_factor";

pub(crate) fn brute_force_row(row: &PgRow) -> Result<BruteForce, StorageError> {
    Ok(BruteForce {
        protected: row.try_get("brute_force_protected")?,
        permanent_lockout: row.try_get("permanent_lockout")?,
        max_temporary_lockouts: row.try_get("max_temporary_lockouts")?,
        strategy: row.try_get("brute_force_strategy")?,
        max_failure_wait_seconds: row.try_get("max_failure_wait_seconds")?,
        minimum_quick_login_wait_seconds: row.try_get("minimum_quick_login_wait_seconds")?,
        wait_increment_seconds: row.try_get("wait_increment_seconds")?,
        quick_login_check_milli_seconds: row.try_get("quick_login_check_milli_seconds")?,
        max_delta_time_seconds: row.try_get("max_delta_time_seconds")?,
        failure_factor: row.try_get("failure_factor")?,
    })
}

/// The realm columns [`login_settings_row`] reads, with
/// [`BRUTE_FORCE_COLUMNS`].
pub(crate) const LOGIN_SETTING_COLUMNS: &str = "remember_me, sso_session_idle_timeout_remember_me, sso_session_max_lifespan_remember_me, registration_allowed, otp_policy_type, otp_policy_algorithm, otp_policy_digits, otp_policy_period, otp_policy_look_ahead, otp_policy_initial_counter, otp_policy_code_reusable";

pub(crate) fn login_settings_row(row: &PgRow) -> Result<LoginSettings, StorageError> {
    Ok(LoginSettings {
        remember_me: row.try_get("remember_me")?,
        sso_session_idle_timeout_remember_me: row
            .try_get("sso_session_idle_timeout_remember_me")?,
        sso_session_max_lifespan_remember_me: row
            .try_get("sso_session_max_lifespan_remember_me")?,
        registration_allowed: row.try_get("registration_allowed")?,
        otp_policy: OtpPolicy {
            kind: row.try_get("otp_policy_type")?,
            algorithm: row.try_get("otp_policy_algorithm")?,
            digits: row.try_get("otp_policy_digits")?,
            period: row.try_get("otp_policy_period")?,
            look_ahead: row.try_get("otp_policy_look_ahead")?,
            initial_counter: row.try_get("otp_policy_initial_counter")?,
            code_reusable: row.try_get("otp_policy_code_reusable")?,
        },
        brute_force: brute_force_row(row)?,
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
        .execute(&mut *connection)
        .await?;
    let brute = &changes.brute_force;
    sqlx::query("UPDATE realms SET brute_force_protected = COALESCE($2, brute_force_protected), permanent_lockout = COALESCE($3, permanent_lockout), max_temporary_lockouts = COALESCE($4, max_temporary_lockouts), brute_force_strategy = COALESCE($5, brute_force_strategy), max_failure_wait_seconds = COALESCE($6, max_failure_wait_seconds), minimum_quick_login_wait_seconds = COALESCE($7, minimum_quick_login_wait_seconds), wait_increment_seconds = COALESCE($8, wait_increment_seconds), quick_login_check_milli_seconds = COALESCE($9, quick_login_check_milli_seconds), max_delta_time_seconds = COALESCE($10, max_delta_time_seconds), failure_factor = COALESCE($11, failure_factor) WHERE name = $1")
        .bind(realm)
        .bind(brute.protected)
        .bind(brute.permanent_lockout)
        .bind(brute.max_temporary_lockouts)
        .bind(brute.strategy.as_deref())
        .bind(brute.max_failure_wait_seconds)
        .bind(brute.minimum_quick_login_wait_seconds)
        .bind(brute.wait_increment_seconds)
        .bind(brute.quick_login_check_milli_seconds)
        .bind(brute.max_delta_time_seconds)
        .bind(brute.failure_factor)
        .execute(&mut *connection)
        .await?;
    if let Some(policy) = &changes.otp_policy {
        sqlx::query("UPDATE realms SET otp_policy_type = $2, otp_policy_algorithm = $3, otp_policy_digits = $4, otp_policy_period = $5, otp_policy_look_ahead = $6, otp_policy_initial_counter = $7, otp_policy_code_reusable = $8 WHERE name = $1")
            .bind(realm)
            .bind(&policy.kind)
            .bind(policy.algorithm.as_deref())
            .bind(policy.digits)
            .bind(policy.period)
            .bind(policy.look_ahead)
            .bind(policy.initial_counter)
            .bind(policy.code_reusable)
            .execute(connection)
            .await?;
    }
    Ok(())
}
