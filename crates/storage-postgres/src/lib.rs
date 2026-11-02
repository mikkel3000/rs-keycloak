//! PostgreSQL schema management and guarded application transactions.

use std::time::Duration;

use sha2::{Digest, Sha256};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{Connection, PgConnection, PgPool, Postgres, Row, Transaction};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const LOCK_KEY: i64 = 0x72736b6579636c;
const MIGRATIONS: &[&str] = &[
    include_str!("../../../migrations/0001_initial.sql"),
    include_str!("../../../migrations/0002_bootstrap.sql"),
    include_str!("../../../migrations/0003_login.sql"),
];
const BOOTSTRAP_LOCK_KEY: i64 = 0x72736b626f6f74;

/// Storage failures are intentionally independent of PostgreSQL error details.
#[derive(Debug, Error)]
pub enum StorageError {
    /// The database could not complete the operation.
    #[error("database operation failed")]
    Database,
    /// A constraint rejected the operation.
    #[error("database constraint rejected the operation")]
    Constraint,
    /// A transaction can be retried only when its entire body is safe to repeat.
    #[error("transaction conflict")]
    Conflict,
    /// The primary is in recovery or the connection is read-only.
    #[error("database is not a writable PostgreSQL 18 primary")]
    NotWritable,
    /// Schema history is missing, changed, or unsupported.
    #[error("database schema history is missing, corrupt, or unsupported")]
    Schema,
    /// Maintenance is active and requires an explicit successful migration.
    #[error("database is in maintenance")]
    Maintenance,
    /// The master realm or bootstrap admin already exists.
    #[error("master realm or bootstrap admin already exists")]
    AlreadyBootstrapped,
    /// The requested lifetime is outside the supported bounds.
    #[error("invalid login lifetime")]
    InvalidInput,
    /// The configured database timeout or admission budget elapsed.
    #[error("database capacity or timeout exceeded")]
    Timeout,
}

impl From<sqlx::Error> for StorageError {
    fn from(error: sqlx::Error) -> Self {
        match &error {
            sqlx::Error::PoolTimedOut => Self::Timeout,
            sqlx::Error::Database(db) => match db.code().as_deref() {
                Some("40001" | "40P01") => Self::Conflict,
                Some("55P03" | "57014") => Self::Timeout,
                Some(code) if code.starts_with("23") => Self::Constraint,
                Some("25006" | "57P03") => Self::NotWritable,
                _ => Self::Database,
            },
            _ => Self::Database,
        }
    }
}

fn checksum(migration: &str) -> Vec<u8> {
    Sha256::digest(migration.as_bytes()).to_vec()
}

fn valid_history(rows: &[PgRow]) -> bool {
    rows.len() <= MIGRATIONS.len()
        && rows.iter().enumerate().all(|(index, row)| {
            row.try_get::<i64, _>("version").ok() == Some(index as i64 + 1)
                && row.try_get::<Vec<u8>, _>("checksum").ok() == Some(checksum(MIGRATIONS[index]))
        })
}

async fn primary(connection: &mut PgConnection) -> Result<(), StorageError> {
    let row: PgRow = sqlx::query("SELECT pg_is_in_recovery() AS recovery, current_setting('transaction_read_only') AS read_only, current_setting('server_version_num')::integer AS version")
        .fetch_one(connection).await?;
    let version: i32 = row.try_get("version")?;
    if row.try_get::<bool, _>("recovery")?
        || row.try_get::<String, _>("read_only")? != "off"
        || !(180000..190000).contains(&version)
    {
        return Err(StorageError::NotWritable);
    }
    Ok(())
}

async fn history(connection: &mut PgConnection) -> Result<(), StorageError> {
    let rows = sqlx::query("SELECT version, checksum FROM rs_schema_history ORDER BY version")
        .fetch_all(connection)
        .await
        .map_err(|_| StorageError::Schema)?;
    if rows.len() != MIGRATIONS.len() || !valid_history(&rows) {
        return Err(StorageError::Schema);
    }
    Ok(())
}

async fn maintenance(connection: &mut PgConnection) -> Result<(), StorageError> {
    let active: bool =
        sqlx::query_scalar("SELECT active FROM rs_maintenance WHERE singleton = true")
            .fetch_one(connection)
            .await
            .map_err(|_| StorageError::Schema)?;
    if active {
        return Err(StorageError::Maintenance);
    }
    Ok(())
}

/// Check writable primary, maintenance gate, and the supported schema without modifying it.
pub async fn check(database_url: &str) -> Result<(), StorageError> {
    tokio::time::timeout(Duration::from_secs(5), check_inner(database_url))
        .await
        .map_err(|_| StorageError::Timeout)?
}

async fn check_inner(database_url: &str) -> Result<(), StorageError> {
    let mut connection =
        tokio::time::timeout(Duration::from_secs(5), PgConnection::connect(database_url))
            .await
            .map_err(|_| StorageError::Timeout)??;
    sqlx::raw_sql("SET search_path = public, pg_catalog; SET lock_timeout = '500ms'; SET statement_timeout = '2s'").execute(&mut connection).await?;
    primary(&mut connection).await?;
    let mut tx = connection.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(LOCK_KEY)
        .execute(&mut *tx)
        .await?;
    maintenance(&mut tx).await?;
    history(&mut tx).await?;
    tx.commit().await?;
    Ok(())
}

/// Apply ordered, checksummed migrations under an exclusive maintenance lock.
/// A failed migration keeps the persisted maintenance gate closed.
pub async fn migrate(database_url: &str) -> Result<(), StorageError> {
    tokio::time::timeout(Duration::from_secs(70), migrate_inner(database_url))
        .await
        .map_err(|_| StorageError::Timeout)?
}

async fn migrate_inner(database_url: &str) -> Result<(), StorageError> {
    let mut connection =
        tokio::time::timeout(Duration::from_secs(5), PgConnection::connect(database_url))
            .await
            .map_err(|_| StorageError::Timeout)??;
    sqlx::raw_sql("SET lock_timeout = '5s'; SET statement_timeout = '60s'; SET search_path = public, pg_catalog")
        .execute(&mut connection).await?;
    primary(&mut connection).await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(LOCK_KEY)
        .execute(&mut connection)
        .await?;
    // Reject unknown history before changing maintenance state or any schema objects.
    let metadata: (bool, bool) = sqlx::query_as("SELECT to_regclass('public.rs_maintenance') IS NOT NULL, to_regclass('public.rs_schema_history') IS NOT NULL")
        .fetch_one(&mut connection).await?;
    if metadata.0 != metadata.1 {
        return Err(StorageError::Schema);
    }
    if metadata.0 {
        let rows = sqlx::query("SELECT version, checksum FROM rs_schema_history ORDER BY version")
            .fetch_all(&mut connection)
            .await
            .map_err(|_| StorageError::Schema)?;
        if !valid_history(&rows) {
            return Err(StorageError::Schema);
        }
        let active: bool =
            sqlx::query_scalar("SELECT active FROM rs_maintenance WHERE singleton = true")
                .fetch_one(&mut connection)
                .await
                .map_err(|_| StorageError::Schema)?;
        if rows.is_empty() && !active {
            return Err(StorageError::Schema);
        }
    }
    // This state commits before DDL, so disconnect or rollback cannot reopen traffic.
    sqlx::raw_sql("CREATE TABLE IF NOT EXISTS rs_maintenance (singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton), active boolean NOT NULL); CREATE TABLE IF NOT EXISTS rs_schema_history (version bigint PRIMARY KEY, checksum bytea NOT NULL, applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP); INSERT INTO rs_maintenance (singleton, active) VALUES (true, true) ON CONFLICT (singleton) DO UPDATE SET active = true;")
        .execute(&mut connection).await?;
    let rows = sqlx::query("SELECT version, checksum FROM rs_schema_history ORDER BY version")
        .fetch_all(&mut connection)
        .await?;
    if !valid_history(&rows) {
        return Err(StorageError::Schema);
    }
    for (index, migration) in MIGRATIONS.iter().enumerate().skip(rows.len()) {
        let mut tx = connection.begin().await?;
        sqlx::raw_sql(migration).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO rs_schema_history (version, checksum) VALUES ($1, $2)")
            .bind(index as i64 + 1)
            .bind(checksum(migration))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    sqlx::query("UPDATE rs_maintenance SET active = false WHERE singleton = true")
        .execute(&mut connection)
        .await?;
    Ok(())
}

/// A stored password hash and revisions to recheck after verification.
/// Password hashes must not be logged or returned to a client.
pub struct LoginCredential {
    /// Stored password hash in PHC format.
    pub phc: Vec<u8>,
    /// User revision observed when the challenge was created.
    pub user_revision: i64,
    /// Credential revision observed when the challenge was created.
    pub credential_revision: i64,
}

/// Result of completing a single-use login challenge.
pub enum LoginOutcome {
    /// Password and current account state permitted session creation.
    Authenticated,
    /// The challenge, account, client, password, or lockout did not permit login.
    Denied,
}

/// Separate bounded request and worker pools for primary-only access.
pub struct Storage {
    request: PgPool,
    worker: PgPool,
    non_auth: Arc<Semaphore>,
}

async fn pool(url: &str, connections: u32) -> Result<PgPool, StorageError> {
    Ok(PgPoolOptions::new().max_connections(connections).acquire_timeout(Duration::from_millis(250))
        .after_connect(|connection, _| Box::pin(async move {
            sqlx::query("SELECT set_config('search_path', 'public, pg_catalog', false), set_config('lock_timeout', '500ms', false), set_config('statement_timeout', '2s', false), set_config('idle_in_transaction_session_timeout', '5s', false)").execute(&mut *connection).await?;
            Ok(())
        })).connect(url).await?)
}

impl Storage {
    /// Open pools after validating the current schema and writable primary.
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        check(database_url).await?;
        Ok(Self {
            request: pool(database_url, 24).await?,
            worker: pool(database_url, 4).await?,
            non_auth: Arc::new(Semaphore::new(16)),
        })
    }

    /// Create the master realm and initial administrator once, in one transaction.
    /// The caller must supply a password hash, never a plaintext password.
    pub async fn bootstrap_admin(
        &self,
        user_id: &str,
        credential_id: &str,
        username: &str,
        username_normalized: &str,
        credential_phc: &[u8],
    ) -> Result<(), StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(BOOTSTRAP_LOCK_KEY)
            .execute(&mut *conn)
            .await?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM bootstrap_admin) OR EXISTS (SELECT 1 FROM realms WHERE id = 'master' OR name = 'master')")
            .fetch_one(&mut *conn).await?;
        if exists {
            return Err(StorageError::AlreadyBootstrapped);
        }
        sqlx::query("INSERT INTO realms (id, name) VALUES ('master', 'master')")
            .execute(&mut *conn)
            .await?;
        sqlx::query("INSERT INTO users (realm_id, id, username, username_normalized) VALUES ('master', $1, $2, $3)")
            .bind(user_id).bind(username).bind(username_normalized).execute(&mut *conn).await?;
        sqlx::query("INSERT INTO credentials (realm_id, id, user_id, credential_type, secret_data) VALUES ('master', $1, $2, 'password', $3)")
            .bind(credential_id).bind(user_id).bind(credential_phc).execute(&mut *conn).await?;
        sqlx::query("INSERT INTO roles (realm_id, id, name) VALUES ('master', 'admin', 'admin')")
            .execute(&mut *conn)
            .await?;
        sqlx::query("INSERT INTO user_role_grants (realm_id, user_id, role_id) VALUES ('master', $1, 'admin')").bind(user_id).execute(&mut *conn).await?;
        sqlx::query("INSERT INTO bootstrap_admin (realm_id, user_id) VALUES ('master', $1)")
            .bind(user_id)
            .execute(&mut *conn)
            .await?;
        sqlx::query("INSERT INTO audit_events (realm_id, actor_user_id, event_type) VALUES ('master', $1, 'bootstrap_admin_created')").bind(user_id).execute(&mut *conn).await?;
        tx.commit().await
    }

    /// Create a short-lived login challenge and return the password hash for verification.
    /// The caller must use opaque, unpredictable challenge IDs and equalize external failure behavior.
    pub async fn start_login(
        &self,
        realm_id: &str,
        client_id: &str,
        username_normalized: &str,
        challenge_id: &str,
        ttl_seconds: i32,
    ) -> Result<Option<LoginCredential>, StorageError> {
        if !(1..=300).contains(&ttl_seconds) {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        // Amortize expiry cleanup without waiting for rows held by other requests.
        sqlx::query("DELETE FROM login_challenges WHERE id IN (SELECT id FROM login_challenges WHERE expires_at <= clock_timestamp() ORDER BY expires_at LIMIT 16 FOR UPDATE SKIP LOCKED)")
            .execute(&mut *conn).await?;
        let row = sqlx::query("SELECT u.id AS user_id, u.revision AS user_revision, c.id AS credential_id, c.revision AS credential_revision, c.secret_data FROM users u JOIN realms r ON r.id = u.realm_id JOIN clients cl ON cl.realm_id = u.realm_id AND cl.id = $2 JOIN credentials c ON c.realm_id = u.realm_id AND c.user_id = u.id AND c.credential_type = 'password' WHERE u.realm_id = $1 AND u.username_normalized = $3 AND u.enabled AND r.enabled AND cl.enabled FOR SHARE OF r, cl FOR UPDATE OF u, c")
            .bind(realm_id).bind(client_id).bind(username_normalized).fetch_optional(&mut *conn).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let user_id: String = row.try_get("user_id")?;
        sqlx::query(
            "INSERT INTO login_lockouts (realm_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(realm_id)
        .bind(&user_id)
        .execute(&mut *conn)
        .await?;
        let locked: bool = sqlx::query_scalar("SELECT COALESCE(locked_until > clock_timestamp(), false) FROM login_lockouts WHERE realm_id = $1 AND user_id = $2 FOR UPDATE").bind(realm_id).bind(&user_id).fetch_one(&mut *conn).await?;
        if locked {
            return Ok(None);
        }
        let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM login_challenges WHERE realm_id = $1 AND user_id = $2 AND consumed_at IS NULL AND expires_at > clock_timestamp()")
            .bind(realm_id).bind(&user_id).fetch_one(&mut *conn).await?;
        if pending >= 5 {
            return Ok(None);
        }
        sqlx::query("INSERT INTO login_challenges (id, realm_id, user_id, client_id, credential_id, user_revision, credential_revision, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, clock_timestamp() + make_interval(secs => $8))")
            .bind(challenge_id).bind(realm_id).bind(&user_id).bind(client_id).bind(row.try_get::<String, _>("credential_id")?).bind(row.try_get::<i64, _>("user_revision")?).bind(row.try_get::<i64, _>("credential_revision")?).bind(f64::from(ttl_seconds)).execute(&mut *conn).await?;
        let credential = LoginCredential {
            phc: row.try_get("secret_data")?,
            user_revision: row.try_get("user_revision")?,
            credential_revision: row.try_get("credential_revision")?,
        };
        tx.commit().await?;
        Ok(Some(credential))
    }

    /// Consume a challenge once and create a session only after rechecking revisions and policy.
    /// The caller verifies the hash outside the transaction and supplies an unpredictable session ID.
    pub async fn finish_login(
        &self,
        challenge_id: &str,
        user_revision: i64,
        credential_revision: i64,
        password_valid: bool,
        session_id: &str,
        session_ttl_seconds: i32,
    ) -> Result<LoginOutcome, StorageError> {
        if !(1..=86400).contains(&session_ttl_seconds) {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let challenge = sqlx::query("UPDATE login_challenges SET consumed_at = CURRENT_TIMESTAMP WHERE id = $1 AND consumed_at IS NULL AND expires_at > clock_timestamp() RETURNING realm_id, user_id, client_id, credential_id, user_revision, credential_revision")
            .bind(challenge_id).fetch_optional(&mut *conn).await?;
        let Some(challenge) = challenge else {
            return Ok(LoginOutcome::Denied);
        };
        let realm: String = challenge.try_get("realm_id")?;
        let user: String = challenge.try_get("user_id")?;
        let client: String = challenge.try_get("client_id")?;
        let credential: String = challenge.try_get("credential_id")?;
        let row = sqlx::query("SELECT u.revision AS user_revision, c.revision AS credential_revision, u.enabled AND r.enabled AND cl.enabled AS enabled FROM users u JOIN realms r ON r.id = u.realm_id JOIN clients cl ON cl.realm_id = u.realm_id AND cl.id = $3 JOIN credentials c ON c.realm_id = u.realm_id AND c.user_id = u.id AND c.id = $4 AND c.credential_type = 'password' WHERE u.realm_id = $1 AND u.id = $2 FOR SHARE OF r, cl FOR UPDATE OF u, c")
            .bind(&realm).bind(&user).bind(&client).bind(&credential).fetch_optional(&mut *conn).await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(LoginOutcome::Denied);
        };
        let locked: bool = sqlx::query_scalar("SELECT COALESCE(locked_until > clock_timestamp(), false) FROM login_lockouts WHERE realm_id = $1 AND user_id = $2 FOR UPDATE").bind(&realm).bind(&user).fetch_one(&mut *conn).await?;
        let current = challenge.try_get::<i64, _>("user_revision")? == user_revision
            && challenge.try_get::<i64, _>("credential_revision")? == credential_revision
            && row.try_get::<bool, _>("enabled")?
            && row.try_get::<i64, _>("user_revision")? == user_revision
            && row.try_get::<i64, _>("credential_revision")? == credential_revision;
        if !current || locked {
            tx.commit().await?;
            return Ok(LoginOutcome::Denied);
        }
        if !password_valid {
            sqlx::query("UPDATE login_lockouts l SET failures = CASE WHEN l.locked_until <= CURRENT_TIMESTAMP THEN 1 ELSE l.failures + 1 END, locked_until = CASE WHEN (CASE WHEN l.locked_until <= CURRENT_TIMESTAMP THEN 1 ELSE l.failures + 1 END) >= COALESCE(p.max_failures, 5) THEN CURRENT_TIMESTAMP + make_interval(secs => COALESCE(p.lock_seconds, 60)) ELSE NULL END FROM realms r LEFT JOIN login_policy p ON p.realm_id = r.id WHERE l.realm_id = r.id AND l.realm_id = $1 AND l.user_id = $2")
                .bind(&realm).bind(&user).execute(&mut *conn).await?;
            tx.commit().await?;
            return Ok(LoginOutcome::Denied);
        }
        sqlx::query("UPDATE login_lockouts SET failures = 0, locked_until = NULL WHERE realm_id = $1 AND user_id = $2").bind(&realm).bind(&user).execute(&mut *conn).await?;
        sqlx::query("INSERT INTO user_sessions (realm_id, id, user_id, expires_at) VALUES ($1, $2, $3, CURRENT_TIMESTAMP + make_interval(secs => $4))").bind(&realm).bind(session_id).bind(&user).bind(f64::from(session_ttl_seconds)).execute(&mut *conn).await?;
        sqlx::query("INSERT INTO client_sessions (realm_id, id, user_session_id, client_id) VALUES ($1, $2, $2, $3)").bind(&realm).bind(session_id).bind(&client).execute(&mut *conn).await?;
        tx.commit().await?;
        Ok(LoginOutcome::Authenticated)
    }

    /// Delete at most `limit` expired login challenges using the worker pool.
    pub async fn cleanup_expired_login_challenges(&self, limit: i64) -> Result<u64, StorageError> {
        if !(1..=1000).contains(&limit) {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_worker().await?;
        let deleted = sqlx::query("DELETE FROM login_challenges WHERE id IN (SELECT id FROM login_challenges WHERE expires_at <= clock_timestamp() ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED)")
            .bind(limit).execute(tx.connection()).await?.rows_affected();
        tx.commit().await?;
        Ok(deleted)
    }

    /// Begin a guarded request transaction; non-auth requests share sixteen slots.
    pub async fn begin_request(&self, auth: bool) -> Result<GuardedTransaction, StorageError> {
        let permit = if auth {
            None
        } else {
            Some(
                tokio::time::timeout(
                    Duration::from_millis(250),
                    self.non_auth.clone().acquire_owned(),
                )
                .await
                .map_err(|_| StorageError::Timeout)?
                .map_err(|_| StorageError::Database)?,
            )
        };
        Self::begin(&self.request, permit).await
    }

    /// Begin a guarded worker transaction on the separate worker pool.
    pub async fn begin_worker(&self) -> Result<GuardedTransaction, StorageError> {
        Self::begin(&self.worker, None).await
    }

    async fn begin(
        pool: &PgPool,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Result<GuardedTransaction, StorageError> {
        let mut tx = pool.begin().await?;
        primary(&mut tx).await?;
        sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
            .bind(LOCK_KEY)
            .execute(&mut *tx)
            .await?;
        maintenance(&mut tx).await?;
        history(&mut tx).await?;
        Ok(GuardedTransaction {
            transaction: tx,
            _permit: permit,
        })
    }
}

/// A transaction holding the shared maintenance lock for its entire lifetime.
pub struct GuardedTransaction {
    transaction: Transaction<'static, Postgres>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl GuardedTransaction {
    /// Access the connection while retaining the maintenance lock.
    pub fn connection(&mut self) -> &mut PgConnection {
        &mut self.transaction
    }
    /// Commit the transaction before returning its result to a caller.
    pub async fn commit(self) -> Result<(), StorageError> {
        self.transaction.commit().await.map_err(Into::into)
    }
}
