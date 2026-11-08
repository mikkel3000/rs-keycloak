//! Brute-force detection on the login form, as the reference's
//! `DefaultBruteForceProtector`: failures of a known user's password are
//! counted while the realm is protected, enough of them lock the user for
//! a growing wait or disable them, and a success clears the count.

use sqlx::{PgConnection, Row};

use crate::login_settings::{BRUTE_FORCE_COLUMNS, BruteForce, brute_force_row};
use crate::{Actor, Storage, StorageError, audit};

/// The reason permanent lockout gives a user it disables.
pub(crate) const PERMANENT_LOCKOUT: &str = "permanentLockout";

/// A user's failure record, as `UserLoginFailureModel`; times in Unix
/// milliseconds, the lock's end in Unix seconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Failures {
    num_failures: i32,
    num_temporary_lockouts: i32,
    last_failure: i64,
    failed_login_not_before: i64,
}

/// What a failure at `now` makes of the record, and whether it locks the
/// user permanently.
fn after_failure(settings: &BruteForce, mut failures: Failures, now: i64) -> (Failures, bool) {
    let permanent_only = settings.permanent_lockout && settings.max_temporary_lockouts == 0;
    let delta = if failures.last_failure > 0 {
        now - failures.last_failure
    } else {
        0
    };
    // Failures further apart than maxDeltaTimeSeconds start a new count.
    if !permanent_only && delta > i64::from(settings.max_delta_time_seconds) * 1000 {
        failures = Failures::default();
    }
    failures.last_failure = now;
    failures.num_failures = failures.num_failures.saturating_add(1);
    let count = i64::from(failures.num_failures);
    let factor = i64::from(settings.failure_factor);
    let increment = i64::from(settings.wait_increment_seconds);
    let mut wait = if permanent_only {
        0
    } else if settings.strategy == "LINEAR" {
        increment * (1 + count - factor)
    } else {
        increment * count.checked_div(factor).unwrap_or(0)
    };
    let mut quick = false;
    if wait <= 0 && delta > 0 && delta < settings.quick_login_check_milli_seconds {
        wait = i64::from(settings.minimum_quick_login_wait_seconds);
        quick = true;
    }
    if wait > 0 {
        if !settings.permanent_lockout || settings.max_temporary_lockouts > 0 {
            wait = wait.min(i64::from(settings.max_failure_wait_seconds));
        }
        if !quick {
            failures.num_temporary_lockouts = failures.num_temporary_lockouts.saturating_add(1);
        }
        if quick
            || !settings.permanent_lockout
            || failures.num_temporary_lockouts <= settings.max_temporary_lockouts
        {
            failures.failed_login_not_before = (now / 1000 + wait).min(i64::from(i32::MAX));
        }
    }
    let permanent = settings.permanent_lockout
        && (failures.num_temporary_lockouts > settings.max_temporary_lockouts
            || settings.max_temporary_lockouts == 0
                && failures.num_failures >= settings.failure_factor);
    (failures, permanent)
}

async fn settings(
    connection: &mut PgConnection,
    realm_id: &str,
) -> Result<BruteForce, StorageError> {
    let row = sqlx::query(&format!(
        "SELECT {BRUTE_FORCE_COLUMNS} FROM realms WHERE id = $1"
    ))
    .bind(realm_id)
    .fetch_one(connection)
    .await?;
    brute_force_row(&row)
}

/// Whether a protected realm has the user temporarily locked.
pub(crate) async fn locked(
    connection: &mut PgConnection,
    realm_id: &str,
    user_id: &str,
) -> Result<bool, StorageError> {
    Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM login_failures f JOIN realms r ON r.id = f.realm_id WHERE f.realm_id = $1 AND f.user_id = $2 AND r.brute_force_protected AND f.failed_login_not_before > floor(EXTRACT(EPOCH FROM clock_timestamp())))")
        .bind(realm_id).bind(user_id).fetch_one(connection).await?)
}

/// Counts a wrong password of a known user, if the realm is protected.
pub(crate) async fn record_failure(
    connection: &mut PgConnection,
    realm_id: &str,
    user_id: &str,
    address: Option<&str>,
) -> Result<(), StorageError> {
    let settings = settings(&mut *connection, realm_id).await?;
    if !settings.protected {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO login_failures (realm_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(realm_id)
    .bind(user_id)
    .execute(&mut *connection)
    .await?;
    let row = sqlx::query("SELECT num_failures, num_temporary_lockouts, last_failure, failed_login_not_before, floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint AS now FROM login_failures WHERE realm_id = $1 AND user_id = $2 FOR UPDATE")
        .bind(realm_id).bind(user_id).fetch_one(&mut *connection).await?;
    let current = Failures {
        num_failures: row.try_get("num_failures")?,
        num_temporary_lockouts: row.try_get("num_temporary_lockouts")?,
        last_failure: row.try_get("last_failure")?,
        failed_login_not_before: row.try_get("failed_login_not_before")?,
    };
    let (next, permanent) = after_failure(&settings, current, row.try_get("now")?);
    sqlx::query("UPDATE login_failures SET num_failures = $3, num_temporary_lockouts = $4, last_failure = $5, failed_login_not_before = $6, last_ip_failure = $7 WHERE realm_id = $1 AND user_id = $2")
        .bind(realm_id).bind(user_id).bind(next.num_failures).bind(next.num_temporary_lockouts)
        .bind(next.last_failure).bind(next.failed_login_not_before).bind(address)
        .execute(&mut *connection).await?;
    if permanent {
        sqlx::query("UPDATE users SET enabled = false, disabled_reason = $3, revision = revision + 1 WHERE realm_id = $1 AND id = $2")
            .bind(realm_id).bind(user_id).bind(PERMANENT_LOCKOUT).execute(connection).await?;
    }
    Ok(())
}

/// Forgets a user's failures after a successful login.
pub(crate) async fn clear(
    connection: &mut PgConnection,
    realm_id: &str,
    user_id: &str,
) -> Result<(), StorageError> {
    sqlx::query("DELETE FROM login_failures WHERE realm_id = $1 AND user_id = $2")
        .bind(realm_id)
        .bind(user_id)
        .execute(connection)
        .await?;
    Ok(())
}

/// A user's brute-force state, as the attack-detection endpoint shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BruteForceStatus {
    /// Locked for now, or disabled by permanent lockout.
    pub disabled: bool,
    /// Counted failures.
    pub num_failures: i32,
    /// Temporary lockouts so far.
    pub num_temporary_lockouts: i32,
    /// The last failure in Unix milliseconds, 0 if none.
    pub last_failure: i64,
    /// Where the last failure came from, `n/a` if none.
    pub last_ip_failure: String,
    /// The temporary lock's end in Unix seconds, `i64::MAX` when locked
    /// permanently, 0 when not disabled.
    pub failed_login_not_before: i64,
}

impl Default for BruteForceStatus {
    fn default() -> Self {
        Self {
            disabled: false,
            num_failures: 0,
            num_temporary_lockouts: 0,
            last_failure: 0,
            last_ip_failure: "n/a".into(),
            failed_login_not_before: 0,
        }
    }
}

impl Storage {
    /// A user's state, with the defaults when the realm is unprotected or
    /// nothing is counted, as `AttackDetectionResource` answers even for
    /// unknown users.
    pub async fn brute_force_status(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<BruteForceStatus, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let row = sqlx::query("SELECT f.num_failures, f.num_temporary_lockouts, f.last_failure, f.last_ip_failure, f.failed_login_not_before, f.failed_login_not_before > floor(EXTRACT(EPOCH FROM clock_timestamp())) AS temporary, COALESCE(NOT u.enabled AND u.disabled_reason = $3, false) AS permanent FROM login_failures f JOIN realms r ON r.id = f.realm_id LEFT JOIN users u ON u.realm_id = f.realm_id AND u.id = f.user_id WHERE f.realm_id = $1 AND f.user_id = $2 AND r.brute_force_protected")
            .bind(realm_id).bind(user_id).bind(PERMANENT_LOCKOUT).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        let Some(row) = row else {
            return Ok(BruteForceStatus::default());
        };
        let temporary: bool = row.try_get("temporary")?;
        let permanent: bool = row.try_get("permanent")?;
        Ok(BruteForceStatus {
            disabled: temporary || permanent,
            num_failures: row.try_get("num_failures")?,
            num_temporary_lockouts: row.try_get("num_temporary_lockouts")?,
            last_failure: row.try_get("last_failure")?,
            last_ip_failure: row
                .try_get::<Option<String>, _>("last_ip_failure")?
                .unwrap_or_else(|| "n/a".into()),
            failed_login_not_before: if temporary {
                row.try_get("failed_login_not_before")?
            } else if permanent {
                i64::MAX
            } else {
                0
            },
        })
    }

    /// Forgets the failures of one user, or of every user in the realm.
    pub async fn clear_brute_force(
        &self,
        realm_id: &str,
        user_id: Option<&str>,
        actor: &Actor,
    ) -> Result<(), StorageError> {
        let mut tx = self.begin_request(false).await?;
        sqlx::query(
            "DELETE FROM login_failures WHERE realm_id = $1 AND ($2::text IS NULL OR user_id = $2)",
        )
        .bind(realm_id)
        .bind(user_id)
        .execute(tx.connection())
        .await?;
        audit(tx.connection(), actor, "brute_force_cleared").await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{BruteForce, Failures, after_failure};

    fn settings(permanent_lockout: bool, failure_factor: i32) -> BruteForce {
        BruteForce {
            protected: true,
            permanent_lockout,
            max_temporary_lockouts: 0,
            strategy: "MULTIPLE".into(),
            max_failure_wait_seconds: 900,
            minimum_quick_login_wait_seconds: 60,
            wait_increment_seconds: 60,
            quick_login_check_milli_seconds: 1000,
            max_delta_time_seconds: 43200,
            failure_factor,
        }
    }

    #[test]
    fn failure_factor_failures_lock_for_the_increment() {
        let start = 1_000_000_000_000;
        let (one, _) = after_failure(&settings(false, 2), Failures::default(), start);
        assert_eq!((one.num_failures, one.failed_login_not_before), (1, 0));
        let (two, permanent) = after_failure(&settings(false, 2), one, start + 5000);
        assert_eq!(two.num_temporary_lockouts, 1);
        assert_eq!(two.failed_login_not_before, start / 1000 + 5 + 60);
        assert!(!permanent);
    }

    #[test]
    fn quick_failures_lock_without_counting_a_lockout() {
        let start = 1_000_000_000_000;
        let (one, _) = after_failure(&settings(false, 30), Failures::default(), start);
        let (two, _) = after_failure(&settings(false, 30), one, start + 200);
        assert_eq!(two.num_temporary_lockouts, 0);
        assert_eq!(two.failed_login_not_before, start / 1000 + 60);
    }

    #[test]
    fn permanent_lockout_comes_at_the_failure_factor() {
        let start = 1_000_000_000_000;
        let (one, permanent) = after_failure(&settings(true, 2), Failures::default(), start);
        assert!(!permanent);
        let (_, permanent) = after_failure(&settings(true, 2), one, start + 5000);
        assert!(permanent);
    }

    #[test]
    fn failures_far_apart_start_a_new_count() {
        let start = 1_000_000_000_000;
        let (one, _) = after_failure(&settings(false, 2), Failures::default(), start);
        let (two, _) = after_failure(&settings(false, 2), one, start + 43_201_000);
        assert_eq!((two.num_failures, two.failed_login_not_before), (1, 0));
    }
}
