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
