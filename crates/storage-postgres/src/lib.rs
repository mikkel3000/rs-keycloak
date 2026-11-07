//! PostgreSQL schema management and guarded application transactions.

mod account;
mod action_tokens;
mod client_admin;
mod consent;
mod cors;
mod group_admin;
mod login_locale;
mod login_steps;
mod logout;
mod realm_admin;
mod role_admin;
mod service_account;
mod session_admin;
mod sso;
mod user_admin;

pub use account::{AccountApplication, AccountChange, AccountConflicts, AccountSession};
pub use action_tokens::{ActionToken, LinkUser, RedeemedToken, TokenLookup, VerifyLink};
pub use client_admin::{
    ClientCreation, ClientRecord, ClientUpdate, NewClient, SealedSecret, SecretChange,
};
pub use consent::{ConsentRecord, PendingRequest};
pub use cors::WebOriginCheck;
pub use group_admin::{GroupChange, GroupCreation, GroupRecord, MembershipChange};
pub use login_locale::{LoginLocale, UserLocaleUpdate};
pub use login_steps::{
    CredentialRecord, LoginStep, OtpCredential, Profile, ProfileUpdate, RequiredActionSetting,
};
pub use logout::RefreshLogout;
pub use realm_admin::{
    MASTER_REALM, RealmChanges, RealmCreation, RealmDeletion, RealmRecord, RealmSettings,
    RealmSmtp, UserSettingChanges, UserSettings,
};
pub use role_admin::{
    CompositeChange, NewRole, RoleCreation, RoleDeletion, RoleHolder, RoleMappingChange, RoleNames,
    RoleRecord, RoleUpdate,
};
pub use service_account::{ServiceAccount, ServiceAccountGrant, service_account_username};
pub use session_admin::{ClientSessionCount, SessionRecord};
pub use sso::SsoSession;
pub use user_admin::{NewPassword, NewUser, UserCreation, UserQuery, UserRecord, UserUpdate};

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
    include_str!("../../../migrations/0004_authorization.sql"),
    include_str!("../../../migrations/0005_code_replay_retention.sql"),
    include_str!("../../../migrations/0006_refresh.sql"),
    include_str!("../../../migrations/0007_client_auth.sql"),
    include_str!("../../../migrations/0008_token_revocation.sql"),
    include_str!("../../../migrations/0009_response_mode.sql"),
    include_str!("../../../migrations/0010_client_web_origins.sql"),
    include_str!("../../../migrations/0011_service_accounts.sql"),
    include_str!("../../../migrations/0012_user_profile.sql"),
    include_str!("../../../migrations/0013_sealed_client_secrets.sql"),
    include_str!("../../../migrations/0014_realm_roles.sql"),
    include_str!("../../../migrations/0015_groups.sql"),
    include_str!("../../../migrations/0016_logout.sql"),
    include_str!("../../../migrations/0017_sso_sessions.sql"),
    include_str!("../../../migrations/0018_consent.sql"),
    include_str!("../../../migrations/0019_totp.sql"),
    include_str!("../../../migrations/0020_required_actions.sql"),
    include_str!("../../../migrations/0021_realm_email.sql"),
    include_str!("../../../migrations/0022_reset_credentials.sql"),
    include_str!("../../../migrations/0023_verify_email.sql"),
    include_str!("../../../migrations/0024_update_profile.sql"),
    include_str!("../../../migrations/0025_client_roles.sql"),
    include_str!("../../../migrations/0026_bearer_only.sql"),
    include_str!("../../../migrations/0027_realm_admins.sql"),
    include_str!("../../../migrations/0028_group_roles.sql"),
    include_str!("../../../migrations/0029_client_urls.sql"),
    include_str!("../../../migrations/0030_realm_token_settings.sql"),
    include_str!("../../../migrations/0031_required_action_settings.sql"),
    include_str!("../../../migrations/0032_offline_sessions.sql"),
    include_str!("../../../migrations/0033_account_settings.sql"),
    include_str!("../../../migrations/0034_login_locale.sql"),
];
const BOOTSTRAP_LOCK_KEY: i64 = 0x72736b626f6f74;

/// The user an admin change is recorded against, in the realm that issued
/// the user's token: the master realm, or the realm being managed.
#[derive(Clone, Debug)]
pub struct Actor {
    /// Realm that issued the actor's token.
    pub realm_id: String,
    /// The acting user, a person or a client's service account.
    pub user_id: String,
}

/// Records an admin event against its actor in the current transaction.
async fn audit(
    connection: &mut sqlx::PgConnection,
    actor: &Actor,
    event: &str,
) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT INTO audit_events (realm_id, actor_user_id, event_type) VALUES ($1, $2, $3)",
    )
    .bind(&actor.realm_id)
    .bind(&actor.user_id)
    .bind(event)
    .execute(connection)
    .await?;
    Ok(())
}

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
    /// The client authentication snapshot is invalid or no longer current.
    #[error("client authentication failed")]
    ClientAuth,
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

/// Redirect details saved with an authorization request.
pub struct AuthorizationRedirect {
    /// Response mode saved before the user authenticated.
    pub response_mode: String,
    /// Exact registered redirect URI.
    pub redirect_uri: String,
    /// Optional caller-supplied state.
    pub state: Option<String>,
}

/// Identity and session bound to a consumed authorization code.
pub struct CodeGrant {
    /// Realm identifier.
    pub realm_id: String,
    /// User identifier.
    pub user_id: String,
    /// User session identifier.
    pub session_id: String,
    /// Internal client identifier.
    pub client_id: String,
    /// Public client identifier, used as token audience.
    pub client_identifier: String,
    /// Authorized scopes.
    pub scope: String,
    /// OIDC nonce supplied in the authorization request.
    pub nonce: Option<String>,
    /// Authentication time as Unix seconds.
    pub auth_time: i64,
}

/// Current identity and session state read from the primary.
pub struct ActiveSession {
    /// Realm identifier.
    pub realm_id: String,
    /// User identifier.
    pub user_id: String,
    /// Current username.
    pub username: String,
    /// Session identifier.
    pub session_id: String,
    /// Internal client identifier.
    pub client_id: String,
    /// Public client identifier.
    pub client_identifier: String,
    /// Original authentication time as Unix seconds.
    pub auth_time: i64,
}

fn active_session_row(row: &PgRow) -> Result<ActiveSession, StorageError> {
    Ok(ActiveSession {
        realm_id: row.try_get("realm_id")?,
        user_id: row.try_get("user_id")?,
        username: row.try_get("username")?,
        session_id: row.try_get("session_id")?,
        client_id: row.try_get("client_id")?,
        client_identifier: row.try_get("client_identifier")?,
        auth_time: row.try_get("auth_time")?,
    })
}

/// Access token state, checked in the reference order: client, revocation, session.
pub enum AccessTokenStatus {
    /// The token is unrevoked and its session, user, client and realm are active.
    Active(ActiveSession),
    /// A sessionless token whose client still owns this enabled service account.
    ServiceAccount(ServiceAccount),
    /// No client with the token's authorized party exists in the realm.
    ClientNotFound,
    /// The token ID is on the revocation list.
    Revoked,
    /// No active session binds this user and client.
    SessionNotFound,
}

impl AccessTokenStatus {
    /// Returns the session for an active session-bound token; service-account
    /// tokens and failures yield `None`.
    pub fn into_active(self) -> Option<ActiveSession> {
        match self {
            Self::Active(session) => Some(session),
            Self::ServiceAccount(_)
            | Self::ClientNotFound
            | Self::Revoked
            | Self::SessionNotFound => None,
        }
    }
}

/// Outcome of rotating a refresh token.
pub enum RefreshRotation {
    /// The token was current; a replacement was stored.
    Rotated(RefreshGrant),
    /// The token belongs to the client, but its session has ended.
    SessionNotActive,
    /// The token is an offline token whose offline session has ended.
    OfflineSessionNotFound,
    /// The token is unknown, replayed or expired, or the client changed.
    Invalid,
}

/// Rotated session and the scopes granted to its refresh family.
pub struct RefreshGrant {
    /// Fixed refresh family expiry as Unix seconds.
    pub expires_at: i64,
    /// Current authoritative session state.
    pub session: ActiveSession,
    /// Scope granted to the family.
    pub scope: String,
}

/// Client authentication material read before bounded secret verification.
/// Secret hashes must never be logged or returned to a client.
pub enum ClientAuthMaterial {
    /// No client secret is accepted for this client.
    Public,
    /// The client secret must be verified and its revision rechecked transactionally.
    Confidential {
        /// Stored secret hash in PHC format.
        secret_phc: Vec<u8>,
        /// Revision to recheck after verifying the hash.
        revision: i64,
    },
    /// A recoverable secret sealed with the operator key; open it with
    /// [`client_secret_context`] for this client before comparing.
    Sealed {
        /// Internal client identifier, part of the sealing context.
        client_id: String,
        /// Nonce and AES-256-GCM ciphertext.
        sealed: Vec<u8>,
        /// Identifier of the key that sealed the secret.
        key_id: String,
        /// Revision to recheck after verifying the secret.
        revision: i64,
    },
    /// A confidential client without a secret, which cannot authenticate.
    NoSecret,
}

/// A client's authentication material and whether it is bearer-only.
pub struct ClientAuthEntry {
    /// How the client authenticates.
    pub material: ClientAuthMaterial,
    /// Bearer-only clients may only authenticate to introspection.
    pub bearer_only: bool,
}

/// Lifetime of an offline refresh family, the reference's 30-day default.
const OFFLINE_SESSION_SECONDS: i32 = 30 * 24 * 3600;

/// Whether a granted scope asks for an offline refresh token.
pub fn is_offline_scope(scope: &str) -> bool {
    scope.split(' ').any(|value| value == "offline_access")
}

/// How a client accepts redirect URIs at the authorization endpoint.
pub struct RedirectRules {
    /// Root URL that relative redirect URIs resolve against.
    pub root_url: Option<String>,
    /// Registered redirect URIs, possibly relative or ending in `/*`.
    pub redirect_uris: Vec<String>,
    /// Bearer-only clients never start a login.
    pub bearer_only: bool,
}

/// Associated data that binds a sealed client secret to one client row.
pub fn client_secret_context(realm_id: &str, client_id: &str) -> Vec<u8> {
    [
        b"client-secret\0",
        realm_id.as_bytes(),
        b"\0",
        client_id.as_bytes(),
    ]
    .concat()
}

/// Result of registering a confidential client.
pub enum ConfidentialRegistration {
    /// The client and redirect were created.
    Created,
    /// An exact enabled confidential client and redirect already exist.
    Existing {
        /// Existing PHC hash, for constant-time secret verification by the caller.
        secret_phc: Vec<u8>,
        /// Existing client revision.
        revision: i64,
    },
}

/// Active refresh-token metadata for an authenticated introspection request.
pub struct RefreshIntrospection {
    /// Current session and granted scopes.
    pub grant: RefreshGrant,
    /// Refresh-family expiry as Unix seconds.
    pub expires_at: i64,
}

pub(crate) async fn authenticated_client(
    connection: &mut PgConnection,
    realm: &str,
    client_identifier: &str,
    client_revision: Option<i64>,
) -> Result<String, StorageError> {
    sqlx::query_scalar("SELECT c.id FROM clients c JOIN realms r ON r.id = c.realm_id WHERE c.realm_id = $1 AND c.client_id = $2 AND c.enabled AND r.enabled AND ((c.public_client AND $3::bigint IS NULL) OR (NOT c.public_client AND c.revision = $3)) FOR SHARE OF c, r")
        .bind(realm).bind(client_identifier).bind(client_revision).fetch_optional(connection).await?.ok_or(StorageError::ClientAuth)
}

async fn lookup_access_token(
    connection: &mut PgConnection,
    realm: &str,
    client_identifier: &str,
    session_id: Option<&str>,
    user_id: &str,
    jti_hash: &[u8],
) -> Result<AccessTokenStatus, StorageError> {
    let (client_exists, revoked): (bool, bool) = sqlx::query_as("SELECT EXISTS (SELECT 1 FROM clients WHERE realm_id = $1 AND client_id = $2), EXISTS (SELECT 1 FROM revoked_access_tokens WHERE realm_id = $1 AND jti_hash = $3 AND expires_at > clock_timestamp())")
        .bind(realm).bind(client_identifier).bind(jti_hash).fetch_one(&mut *connection).await?;
    if !client_exists {
        return Ok(AccessTokenStatus::ClientNotFound);
    }
    if revoked {
        return Ok(AccessTokenStatus::Revoked);
    }
    let Some(session_id) = session_id else {
        return service_account::lookup_service_account_token(
            connection,
            realm,
            client_identifier,
            user_id,
        )
        .await;
    };
    let row = sqlx::query("SELECT us.realm_id, us.user_id, u.username, us.id AS session_id, c.id AS client_id, c.client_id AS client_identifier, floor(EXTRACT(EPOCH FROM us.created_at))::bigint AS auth_time FROM user_sessions us JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id JOIN realms r ON r.id = us.realm_id JOIN client_sessions cs ON cs.realm_id = us.realm_id AND cs.user_session_id = us.id JOIN clients c ON c.realm_id = cs.realm_id AND c.id = cs.client_id WHERE us.realm_id = $1 AND c.client_id = $2 AND us.id = $3 AND u.id = $4 AND ((us.revoked_at IS NULL AND us.expires_at > clock_timestamp()) OR EXISTS (SELECT 1 FROM refresh_families f WHERE f.realm_id = us.realm_id AND f.user_session_id = us.id AND f.client_id = c.id AND f.offline AND f.revoked_at IS NULL AND f.expires_at > clock_timestamp())) AND r.enabled AND u.enabled AND c.enabled")
        .bind(realm).bind(client_identifier).bind(session_id).bind(user_id).fetch_optional(connection).await?;
    Ok(match row {
        Some(row) => AccessTokenStatus::Active(active_session_row(&row)?),
        None => AccessTokenStatus::SessionNotFound,
    })
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
        sqlx::query("INSERT INTO user_sessions (realm_id, id, user_id, expires_at, steps_pending) SELECT $1, $2, $3, CURRENT_TIMESTAMP + make_interval(secs => $4), rs_prepare_login_steps($1, $3) FROM users u WHERE u.realm_id = $1 AND u.id = $3").bind(&realm).bind(session_id).bind(&user).bind(f64::from(session_ttl_seconds)).execute(&mut *conn).await?;
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

    /// Resolve an enabled realm's public name to its internal identifier.
    pub async fn realm_id_by_name(&self, name: &str) -> Result<Option<String>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let id = sqlx::query_scalar("SELECT id FROM realms WHERE name = $1 AND enabled")
            .bind(name)
            .fetch_optional(tx.connection())
            .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Register a public client and its exact redirect URI in an existing realm.
    pub async fn create_public_client(
        &self,
        realm: &str,
        client_id: &str,
        client_identifier: &str,
        redirect_uri: &str,
    ) -> Result<(), StorageError> {
        let mut tx = self.begin_request(false).await?;
        let inserted: Option<String> = sqlx::query_scalar("INSERT INTO clients (realm_id, id, client_id, public_client) VALUES ($1, $2, $3, true) ON CONFLICT (realm_id, client_id) DO NOTHING RETURNING id")
            .bind(realm).bind(client_id).bind(client_identifier).fetch_optional(tx.connection()).await?;
        if let Some(id) = inserted {
            sqlx::query("INSERT INTO client_redirect_uris (realm_id, client_id, redirect_uri) VALUES ($1, $2, $3)")
                .bind(realm).bind(id).bind(redirect_uri).execute(tx.connection()).await?;
        } else {
            let matches: bool = sqlx::query_scalar("SELECT c.public_client AND c.enabled AND EXISTS (SELECT 1 FROM client_redirect_uris d WHERE d.realm_id = c.realm_id AND d.client_id = c.id AND d.redirect_uri = $3) FROM clients c WHERE c.realm_id = $1 AND c.client_id = $2 FOR UPDATE")
                .bind(realm).bind(client_identifier).bind(redirect_uri).fetch_one(tx.connection()).await?;
            if !matches {
                return Err(StorageError::Conflict);
            }
        }
        tx.commit().await
    }

    /// Register a confidential client and its redirect without replacing existing credentials.
    pub async fn create_confidential_client(
        &self,
        realm: &str,
        client_id: &str,
        client_identifier: &str,
        redirect_uri: &str,
        secret_phc: &[u8],
    ) -> Result<ConfidentialRegistration, StorageError> {
        if secret_phc.is_empty() || secret_phc.len() > 4096 {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(false).await?;
        let inserted: Option<String> = sqlx::query_scalar("INSERT INTO clients (realm_id, id, client_id, public_client, secret_phc) VALUES ($1, $2, $3, false, $4) ON CONFLICT (realm_id, client_id) DO NOTHING RETURNING id")
            .bind(realm).bind(client_id).bind(client_identifier).bind(secret_phc).fetch_optional(tx.connection()).await?;
        let result = if let Some(id) = inserted {
            sqlx::query("INSERT INTO client_redirect_uris (realm_id, client_id, redirect_uri) VALUES ($1, $2, $3)")
                .bind(realm).bind(id).bind(redirect_uri).execute(tx.connection()).await?;
            ConfidentialRegistration::Created
        } else {
            let row = sqlx::query("SELECT c.secret_phc, c.revision FROM clients c WHERE c.realm_id = $1 AND c.client_id = $2 AND NOT c.public_client AND c.enabled AND EXISTS (SELECT 1 FROM client_redirect_uris d WHERE d.realm_id = c.realm_id AND d.client_id = c.id AND d.redirect_uri = $3) FOR UPDATE")
                .bind(realm).bind(client_identifier).bind(redirect_uri).fetch_optional(tx.connection()).await?;
            let Some(row) = row else {
                return Err(StorageError::Conflict);
            };
            ConfidentialRegistration::Existing {
                secret_phc: row.try_get("secret_phc")?,
                revision: row.try_get("revision")?,
            }
        };
        tx.commit().await?;
        Ok(result)
    }

    /// Read client type and credential for verification outside the transaction.
    pub async fn client_auth_material(
        &self,
        realm: &str,
        client_identifier: &str,
    ) -> Result<Option<ClientAuthEntry>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query("SELECT c.id, c.public_client, c.bearer_only, c.secret_phc, c.secret_sealed, c.secret_key_id, c.revision FROM clients c JOIN realms r ON r.id = c.realm_id WHERE c.realm_id = $1 AND c.client_id = $2 AND c.enabled AND r.enabled")
            .bind(realm).bind(client_identifier).fetch_optional(tx.connection()).await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let material = if row.try_get::<bool, _>("public_client")? {
            ClientAuthMaterial::Public
        } else if let Some(sealed) = row.try_get::<Option<Vec<u8>>, _>("secret_sealed")? {
            ClientAuthMaterial::Sealed {
                client_id: row.try_get("id")?,
                sealed,
                key_id: row.try_get("secret_key_id")?,
                revision: row.try_get("revision")?,
            }
        } else if let Some(secret_phc) = row.try_get::<Option<Vec<u8>>, _>("secret_phc")? {
            ClientAuthMaterial::Confidential {
                secret_phc,
                revision: row.try_get("revision")?,
            }
        } else {
            ClientAuthMaterial::NoSecret
        };
        let bearer_only = row.try_get("bearer_only")?;
        tx.commit().await?;
        Ok(Some(ClientAuthEntry {
            material,
            bearer_only,
        }))
    }

    /// Replace a confidential client secret only if its observed revision is current.
    pub async fn rotate_client_secret(
        &self,
        realm: &str,
        client_identifier: &str,
        expected_revision: i64,
        new_secret_phc: &[u8],
    ) -> Result<bool, StorageError> {
        if new_secret_phc.is_empty() || new_secret_phc.len() > 4096 {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(false).await?;
        let changed = sqlx::query("UPDATE clients SET secret_phc = $4 WHERE realm_id = $1 AND client_id = $2 AND revision = $3 AND NOT public_client AND enabled")
            .bind(realm).bind(client_identifier).bind(expected_revision).bind(new_secret_phc).execute(tx.connection()).await?.rows_affected();
        tx.commit().await?;
        Ok(changed == 1)
    }

    /// Persist an authorization request only for an enabled client and exact redirect.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_authorization_request(
        &self,
        request_id: &str,
        csrf_hash: &[u8],
        realm: &str,
        client_identifier: &str,
        redirect_uri: &str,
        registered_redirect: &str,
        pkce_s256: &[u8],
        state: Option<&str>,
        scope: &str,
        nonce: Option<&str>,
        ttl_seconds: i32,
        response_mode: &str,
        prompt_consent: bool,
        ui_locales: Option<&str>,
    ) -> Result<bool, StorageError> {
        if !matches!(response_mode, "query" | "fragment" | "form_post")
            || !(1..=300).contains(&ttl_seconds)
            || csrf_hash.len() != 32
            || pkce_s256.len() != 32
            || state.is_some_and(|s| s.len() > 2048)
            || scope.is_empty()
            || scope.len() > 2048
            || nonce.is_some_and(|s| s.len() > 2048)
            || ui_locales.is_some_and(|s| s.len() > 2048)
        {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        sqlx::query("DELETE FROM authorization_requests WHERE id IN (SELECT id FROM authorization_requests WHERE expires_at <= clock_timestamp() ORDER BY expires_at LIMIT 16 FOR UPDATE SKIP LOCKED)").execute(&mut *conn).await?;
        let count = sqlx::query("INSERT INTO authorization_requests (id, csrf_hash, realm_id, client_id, redirect_uri, registered_redirect, pkce_s256, state, scope, nonce, expires_at, response_mode, prompt_consent, ui_locales) SELECT $1, $2, r.id, c.id, $5, d.redirect_uri, $6, $7, $8, $9, clock_timestamp() + make_interval(secs => $10), $11, $12, $14 FROM realms r JOIN clients c ON c.realm_id = r.id JOIN client_redirect_uris d ON d.realm_id = c.realm_id AND d.client_id = c.id WHERE r.id = $3 AND c.client_id = $4 AND d.redirect_uri = $13 AND r.enabled AND c.enabled AND c.standard_flow_enabled AND NOT c.bearer_only")
            .bind(request_id).bind(csrf_hash).bind(realm).bind(client_identifier).bind(redirect_uri).bind(pkce_s256).bind(state).bind(scope).bind(nonce).bind(f64::from(ttl_seconds)).bind(response_mode).bind(prompt_consent).bind(registered_redirect).bind(ui_locales)
            .execute(&mut *conn).await?.rows_affected();
        tx.commit().await?;
        Ok(count == 1)
    }

    /// Reads how an enabled client of an enabled realm accepts redirect URIs.
    pub async fn redirect_rules(
        &self,
        realm: &str,
        client_identifier: &str,
    ) -> Result<Option<RedirectRules>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query("SELECT c.root_url, c.bearer_only, ARRAY(SELECT d.redirect_uri FROM client_redirect_uris d WHERE d.realm_id = c.realm_id AND d.client_id = c.id ORDER BY d.redirect_uri) AS redirect_uris FROM clients c JOIN realms r ON r.id = c.realm_id WHERE c.realm_id = $1 AND c.client_id = $2 AND c.enabled AND r.enabled")
            .bind(realm).bind(client_identifier).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        row.map(|row| {
            Ok(RedirectRules {
                root_url: row.try_get("root_url")?,
                redirect_uris: row.try_get("redirect_uris")?,
                bearer_only: row.try_get("bearer_only")?,
            })
        })
        .transpose()
    }

    /// Resolve a live request to its realm and internal client after CSRF binding.
    pub async fn authorization_request_client(
        &self,
        request_id: &str,
        csrf_hash: &[u8],
    ) -> Result<Option<(String, String)>, StorageError> {
        if csrf_hash.len() != 32 {
            return Ok(None);
        }
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query_as("SELECT a.realm_id, a.client_id FROM authorization_requests a JOIN realms r ON r.id = a.realm_id JOIN clients c ON c.realm_id = a.realm_id AND c.id = a.client_id WHERE a.id = $1 AND a.csrf_hash = $2 AND a.consumed_at IS NULL AND a.expires_at > clock_timestamp() AND r.enabled AND c.enabled")
            .bind(request_id).bind(csrf_hash).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Consume an authorization request and bind a hashed code to a live user and client session.
    pub async fn issue_authorization_code(
        &self,
        request_id: &str,
        csrf_hash: &[u8],
        user_session_id: &str,
        code_hash: &[u8],
        ttl_seconds: i32,
    ) -> Result<Option<AuthorizationRedirect>, StorageError> {
        if !(1..=120).contains(&ttl_seconds) || csrf_hash.len() != 32 || code_hash.len() != 32 {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let req = sqlx::query("UPDATE authorization_requests SET consumed_at = clock_timestamp() WHERE id = $1 AND csrf_hash = $2 AND consumed_at IS NULL AND expires_at > clock_timestamp() RETURNING realm_id, client_id, redirect_uri, registered_redirect, pkce_s256, state, scope, nonce, response_mode")
            .bind(request_id).bind(csrf_hash).fetch_optional(&mut *conn).await?;
        let Some(req) = req else {
            return Ok(None);
        };
        let realm: String = req.try_get("realm_id")?;
        let client: String = req.try_get("client_id")?;
        let valid = sqlx::query("SELECT 1 FROM user_sessions us JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id JOIN realms r ON r.id = us.realm_id JOIN client_sessions cs ON cs.realm_id = us.realm_id AND cs.user_session_id = us.id JOIN clients c ON c.realm_id = cs.realm_id AND c.id = cs.client_id WHERE us.realm_id = $1 AND us.id = $2 AND c.id = $3 AND us.expires_at > clock_timestamp() AND us.revoked_at IS NULL AND NOT us.steps_pending AND r.enabled AND u.enabled AND c.enabled FOR SHARE OF us, u, r, cs, c")
            .bind(&realm).bind(user_session_id).bind(&client).fetch_optional(&mut *conn).await?.is_some();
        if !valid {
            tx.commit().await?;
            return Ok(None);
        }
        sqlx::query("DELETE FROM authorization_codes WHERE code_hash IN (SELECT a.code_hash FROM authorization_codes a WHERE a.replay_until <= clock_timestamp() AND NOT EXISTS (SELECT 1 FROM user_sessions us WHERE us.realm_id = a.realm_id AND us.id = a.user_session_id AND us.expires_at > clock_timestamp() AND us.revoked_at IS NULL) ORDER BY a.replay_until LIMIT 16 FOR UPDATE OF a SKIP LOCKED)").execute(&mut *conn).await?;
        let redirect_uri: String = req.try_get("redirect_uri")?;
        sqlx::query("INSERT INTO authorization_codes (code_hash, realm_id, client_id, redirect_uri, registered_redirect, user_session_id, pkce_s256, scope, nonce, expires_at, replay_until) VALUES ($1, $2, $3, $4, $10, $5, $6, $7, $8, clock_timestamp() + make_interval(secs => $9), (SELECT expires_at FROM user_sessions WHERE realm_id = $2 AND id = $5))")
            .bind(code_hash).bind(&realm).bind(&client).bind(&redirect_uri).bind(user_session_id).bind(req.try_get::<Vec<u8>, _>("pkce_s256")?).bind(req.try_get::<String, _>("scope")?).bind(req.try_get::<Option<String>, _>("nonce")?).bind(f64::from(ttl_seconds)).bind(req.try_get::<String, _>("registered_redirect")?).execute(&mut *conn).await?;
        let state = req.try_get("state")?;
        let response_mode = req.try_get("response_mode")?;
        tx.commit().await?;
        Ok(Some(AuthorizationRedirect {
            response_mode,
            redirect_uri,
            state,
        }))
    }

    /// Atomically consume a code with exact realm, client, redirect and PKCE bindings.
    pub async fn redeem_authorization_code(
        &self,
        code_hash: &[u8],
        realm: &str,
        client_identifier: &str,
        redirect_uri: &str,
        pkce_s256: &[u8],
        client_revision: Option<i64>,
    ) -> Result<Option<CodeGrant>, StorageError> {
        if code_hash.len() != 32 || pkce_s256.len() != 32 {
            return Ok(None);
        }
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let code = sqlx::query("SELECT a.realm_id, a.client_id, a.user_session_id, us.user_id, c.client_id AS client_identifier, a.scope, a.nonce, floor(EXTRACT(EPOCH FROM us.created_at))::bigint AS auth_time, a.consumed_at IS NOT NULL AS consumed FROM authorization_codes a JOIN clients c ON c.realm_id = a.realm_id AND c.id = a.client_id JOIN realms r ON r.id = a.realm_id JOIN user_sessions us ON us.realm_id = a.realm_id AND us.id = a.user_session_id JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id JOIN client_sessions cs ON cs.realm_id = us.realm_id AND cs.user_session_id = us.id AND cs.client_id = c.id WHERE a.code_hash = $1 AND a.realm_id = $2 AND c.client_id = $3 AND a.redirect_uri = $4 AND a.pkce_s256 = $5 AND ((c.public_client AND $6::bigint IS NULL) OR (NOT c.public_client AND c.revision = $6)) AND us.expires_at > clock_timestamp() AND us.revoked_at IS NULL AND r.enabled AND c.enabled AND u.enabled FOR UPDATE OF a, us FOR SHARE OF c, r, u, cs")
            .bind(code_hash).bind(realm).bind(client_identifier).bind(redirect_uri).bind(pkce_s256).bind(client_revision).fetch_optional(&mut *conn).await?;
        let Some(code) = code else {
            return Ok(None);
        };
        if code.try_get::<bool, _>("consumed")? {
            sqlx::query("UPDATE user_sessions SET revoked_at = clock_timestamp() WHERE realm_id = $1 AND id = $2 AND revoked_at IS NULL")
                .bind(realm).bind(code.try_get::<String, _>("user_session_id")?).execute(&mut *conn).await?;
            tx.commit().await?;
            return Ok(None);
        }
        let count = sqlx::query("UPDATE authorization_codes SET consumed_at = clock_timestamp() WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > clock_timestamp()").bind(code_hash).execute(&mut *conn).await?.rows_affected();
        if count != 1 {
            tx.commit().await?;
            return Ok(None);
        }
        let result = CodeGrant {
            realm_id: code.try_get("realm_id")?,
            user_id: code.try_get("user_id")?,
            session_id: code.try_get("user_session_id")?,
            client_id: code.try_get("client_id")?,
            client_identifier: code.try_get("client_identifier")?,
            scope: code.try_get("scope")?,
            nonce: code.try_get("nonce")?,
            auth_time: code.try_get("auth_time")?,
        };
        tx.commit().await?;
        Ok(Some(result))
    }

    /// Read current user and session state from the writable primary.
    pub async fn active_session(
        &self,
        realm: &str,
        client_identifier: &str,
        session_id: &str,
        user_id: &str,
    ) -> Result<Option<ActiveSession>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query("SELECT us.realm_id, us.user_id, u.username, us.id AS session_id, c.id AS client_id, c.client_id AS client_identifier, floor(EXTRACT(EPOCH FROM us.created_at))::bigint AS auth_time FROM user_sessions us JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id JOIN realms r ON r.id = us.realm_id JOIN client_sessions cs ON cs.realm_id = us.realm_id AND cs.user_session_id = us.id JOIN clients c ON c.realm_id = cs.realm_id AND c.id = cs.client_id WHERE us.realm_id = $1 AND c.client_id = $2 AND us.id = $3 AND u.id = $4 AND us.revoked_at IS NULL AND us.expires_at > clock_timestamp() AND r.enabled AND u.enabled AND c.enabled")
            .bind(realm).bind(client_identifier).bind(session_id).bind(user_id).fetch_optional(tx.connection()).await?;
        let result = row.as_ref().map(active_session_row).transpose()?;
        tx.commit().await?;
        Ok(result)
    }

    /// Create an initial refresh token family for an enabled client and live session.
    /// The caller verifies JWT signatures and stores only the unpredictable token ID's SHA-256 hash.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_refresh_family(
        &self,
        realm: &str,
        client_identifier: &str,
        session_id: &str,
        family_id: &str,
        token_hash: &[u8],
        scope: &str,
        ttl_seconds: i32,
        client_revision: Option<i64>,
    ) -> Result<Option<i64>, StorageError> {
        if token_hash.len() != 32
            || scope.is_empty()
            || scope.len() > 2048
            || !(1..=86400).contains(&ttl_seconds)
        {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let row = sqlx::query("SELECT c.id FROM user_sessions us JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id JOIN realms r ON r.id = us.realm_id JOIN client_sessions cs ON cs.realm_id = us.realm_id AND cs.user_session_id = us.id JOIN clients c ON c.realm_id = cs.realm_id AND c.id = cs.client_id WHERE us.realm_id = $1 AND c.client_id = $2 AND us.id = $3 AND ((c.public_client AND $4::bigint IS NULL) OR (NOT c.public_client AND c.revision = $4)) AND us.revoked_at IS NULL AND us.expires_at > clock_timestamp() AND r.enabled AND u.enabled AND c.enabled FOR SHARE OF us, u, r, cs, c")
            .bind(realm).bind(client_identifier).bind(session_id).bind(client_revision).fetch_optional(&mut *conn).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let client: String = row.try_get("id")?;
        sqlx::query("DELETE FROM refresh_families WHERE id IN (SELECT id FROM refresh_families WHERE expires_at <= clock_timestamp() ORDER BY expires_at LIMIT 16 FOR UPDATE SKIP LOCKED)").execute(&mut *conn).await?;
        // An offline family lives on its own lifetime; an online one ends
        // with its session.
        let offline = is_offline_scope(scope);
        let expires_at: i64 = sqlx::query_scalar("INSERT INTO refresh_families (id, realm_id, client_id, user_session_id, scope, expires_at, offline) VALUES ($1, $2, $3, $4, $5, CASE WHEN $7 THEN clock_timestamp() + make_interval(secs => $8) ELSE LEAST(clock_timestamp() + make_interval(secs => $6), (SELECT expires_at FROM user_sessions WHERE realm_id = $2 AND id = $4)) END, $7) RETURNING floor(EXTRACT(EPOCH FROM expires_at))::bigint")
            .bind(family_id).bind(realm).bind(&client).bind(session_id).bind(scope).bind(f64::from(ttl_seconds)).bind(offline).bind(f64::from(OFFLINE_SESSION_SECONDS)).fetch_one(&mut *conn).await?;
        sqlx::query(
            "INSERT INTO refresh_tokens (token_hash, family_id, generation) VALUES ($1, $2, 0)",
        )
        .bind(token_hash)
        .bind(family_id)
        .execute(&mut *conn)
        .await?;
        tx.commit().await?;
        Ok(Some(expires_at))
    }

    /// Rotate a refresh token once; correctly bound replay revokes its family and session.
    pub async fn rotate_refresh_token(
        &self,
        realm: &str,
        client_identifier: &str,
        token_hash: &[u8],
        next_token_hash: &[u8],
        client_revision: Option<i64>,
    ) -> Result<RefreshRotation, StorageError> {
        if token_hash.len() != 32 || next_token_hash.len() != 32 || token_hash == next_token_hash {
            return Ok(RefreshRotation::Invalid);
        }
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let row = sqlx::query("SELECT us.realm_id, us.user_id, u.username, us.id AS session_id, c.id AS client_id, c.client_id AS client_identifier, floor(EXTRACT(EPOCH FROM us.created_at))::bigint AS auth_time, f.id AS family_id, floor(EXTRACT(EPOCH FROM f.expires_at))::bigint AS expires_at, f.scope AS scope, f.generation AS family_generation, t.generation AS token_generation, t.consumed_at IS NOT NULL AS consumed FROM refresh_tokens t JOIN refresh_families f ON f.id = t.family_id JOIN user_sessions us ON us.realm_id = f.realm_id AND us.id = f.user_session_id JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id JOIN realms r ON r.id = us.realm_id JOIN clients c ON c.realm_id = f.realm_id AND c.id = f.client_id JOIN client_sessions cs ON cs.realm_id = us.realm_id AND cs.user_session_id = us.id AND cs.client_id = c.id WHERE t.token_hash = $1 AND f.realm_id = $2 AND c.client_id = $3 AND ((c.public_client AND $4::bigint IS NULL) OR (NOT c.public_client AND c.revision = $4)) AND f.revoked_at IS NULL AND f.expires_at > clock_timestamp() AND (f.offline OR (us.revoked_at IS NULL AND us.expires_at > clock_timestamp())) AND r.enabled AND u.enabled AND c.enabled FOR UPDATE OF t, f, us FOR SHARE OF u, r, c, cs")
            .bind(token_hash).bind(realm).bind(client_identifier).bind(client_revision).fetch_optional(&mut *conn).await?;
        let Some(row) = row else {
            // A token of this client whose session has ended is reported
            // separately, as the reference does.
            let issued: Option<bool> = sqlx::query_scalar("SELECT f.offline FROM refresh_tokens t JOIN refresh_families f ON f.id = t.family_id JOIN clients c ON c.realm_id = f.realm_id AND c.id = f.client_id WHERE t.token_hash = $1 AND f.realm_id = $2 AND c.client_id = $3")
                .bind(token_hash).bind(realm).bind(client_identifier).fetch_optional(&mut *conn).await?;
            tx.commit().await?;
            return Ok(match issued {
                Some(true) => RefreshRotation::OfflineSessionNotFound,
                Some(false) => RefreshRotation::SessionNotActive,
                None => RefreshRotation::Invalid,
            });
        };
        let family: String = row.try_get("family_id")?;
        let session: String = row.try_get("session_id")?;
        if row.try_get::<bool, _>("consumed")?
            || row.try_get::<i64, _>("token_generation")?
                != row.try_get::<i64, _>("family_generation")?
        {
            sqlx::query("UPDATE refresh_families SET revoked_at = clock_timestamp() WHERE id = $1")
                .bind(&family)
                .execute(&mut *conn)
                .await?;
            sqlx::query("UPDATE user_sessions SET revoked_at = clock_timestamp() WHERE realm_id = $1 AND id = $2").bind(realm).bind(session).execute(&mut *conn).await?;
            tx.commit().await?;
            return Ok(RefreshRotation::Invalid);
        }
        sqlx::query("UPDATE refresh_tokens SET consumed_at = clock_timestamp() WHERE token_hash = $1 AND consumed_at IS NULL").bind(token_hash).execute(&mut *conn).await?;
        let next: i64 = sqlx::query_scalar("UPDATE refresh_families SET generation = generation + 1 WHERE id = $1 AND expires_at > clock_timestamp() AND revoked_at IS NULL RETURNING generation").bind(&family).fetch_one(&mut *conn).await?;
        sqlx::query(
            "INSERT INTO refresh_tokens (token_hash, family_id, generation) VALUES ($1, $2, $3)",
        )
        .bind(next_token_hash)
        .bind(&family)
        .bind(next)
        .execute(&mut *conn)
        .await?;
        let result = RefreshGrant {
            expires_at: row.try_get("expires_at")?,
            session: active_session_row(&row)?,
            scope: row.try_get("scope")?,
        };
        tx.commit().await?;
        Ok(RefreshRotation::Rotated(result))
    }

    /// Check a verified access token against current session state and token revocations.
    pub async fn active_access_token(
        &self,
        realm: &str,
        client_identifier: &str,
        session_id: Option<&str>,
        user_id: &str,
        jti_hash: &[u8],
    ) -> Result<AccessTokenStatus, StorageError> {
        if jti_hash.len() != 32 {
            return Ok(AccessTokenStatus::SessionNotFound);
        }
        let mut tx = self.begin_request(true).await?;
        let result = lookup_access_token(
            tx.connection(),
            realm,
            client_identifier,
            session_id,
            user_id,
            jti_hash,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Introspect a verified access token after rechecking the calling client's authentication.
    #[allow(clippy::too_many_arguments)]
    pub async fn introspect_access_token(
        &self,
        realm: &str,
        client_identifier: &str,
        client_revision: Option<i64>,
        session_id: Option<&str>,
        user_id: &str,
        jti_hash: &[u8],
    ) -> Result<AccessTokenStatus, StorageError> {
        let mut tx = self.begin_request(true).await?;
        authenticated_client(tx.connection(), realm, client_identifier, client_revision).await?;
        let result = if jti_hash.len() == 32 {
            lookup_access_token(
                tx.connection(),
                realm,
                client_identifier,
                session_id,
                user_id,
                jti_hash,
            )
            .await?
        } else {
            AccessTokenStatus::SessionNotFound
        };
        tx.commit().await?;
        Ok(result)
    }

    /// Revoke a verified access token without disclosing whether it belongs to the client.
    #[allow(clippy::too_many_arguments)]
    pub async fn revoke_access_token(
        &self,
        realm: &str,
        client_identifier: &str,
        client_revision: Option<i64>,
        session_id: Option<&str>,
        user_id: &str,
        jti_hash: &[u8],
        expires_at: i64,
    ) -> Result<(), StorageError> {
        let mut tx = self.begin_request(true).await?;
        let client_id =
            authenticated_client(tx.connection(), realm, client_identifier, client_revision)
                .await?;
        let conn = tx.connection();
        if jti_hash.len() == 32 {
            sqlx::query("DELETE FROM revoked_access_tokens WHERE (realm_id, jti_hash) IN (SELECT realm_id, jti_hash FROM revoked_access_tokens WHERE expires_at <= clock_timestamp() ORDER BY expires_at LIMIT 16 FOR UPDATE SKIP LOCKED)").execute(&mut *conn).await?;
            match session_id {
                Some(session_id) => sqlx::query("INSERT INTO revoked_access_tokens (realm_id, jti_hash, session_id, expires_at) SELECT us.realm_id, $5, us.id, LEAST(to_timestamp($6::double precision), us.expires_at) FROM user_sessions us JOIN client_sessions cs ON cs.realm_id = us.realm_id AND cs.user_session_id = us.id WHERE us.realm_id = $1 AND cs.client_id = $2 AND us.id = $3 AND us.user_id = $4 AND to_timestamp($6::double precision) > clock_timestamp() AND us.expires_at > clock_timestamp() ON CONFLICT DO NOTHING")
                    .bind(realm).bind(client_id).bind(session_id).bind(user_id).bind(jti_hash).bind(expires_at as f64).execute(&mut *conn).await?,
                None => sqlx::query("INSERT INTO revoked_access_tokens (realm_id, jti_hash, service_account_user_id, expires_at) SELECT u.realm_id, $4, u.id, to_timestamp($5::double precision) FROM users u WHERE u.realm_id = $1 AND u.service_account_client_id = $2 AND u.id = $3 AND to_timestamp($5::double precision) > clock_timestamp() ON CONFLICT DO NOTHING")
                    .bind(realm).bind(client_id).bind(user_id).bind(jti_hash).bind(expires_at as f64).execute(&mut *conn).await?,
            };
        }
        tx.commit().await?;
        Ok(())
    }

    /// Revoke the bound refresh family; unknown or other-client tokens have the same result.
    pub async fn revoke_refresh_token(
        &self,
        realm: &str,
        client_identifier: &str,
        client_revision: Option<i64>,
        token_hash: &[u8],
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let client_id =
            authenticated_client(tx.connection(), realm, client_identifier, client_revision)
                .await?;
        if token_hash.len() != 32 {
            return Ok(false);
        }
        let conn = tx.connection();
        let row = sqlx::query("SELECT f.id AS family_id, f.offline, us.id AS session_id FROM refresh_tokens t JOIN refresh_families f ON f.id = t.family_id JOIN user_sessions us ON us.realm_id = f.realm_id AND us.id = f.user_session_id JOIN client_sessions cs ON cs.realm_id = us.realm_id AND cs.user_session_id = us.id AND cs.client_id = f.client_id WHERE t.token_hash = $1 AND f.realm_id = $2 AND f.client_id = $3 AND f.revoked_at IS NULL AND (f.offline OR (us.revoked_at IS NULL AND us.expires_at > clock_timestamp())) FOR UPDATE OF t, f, us, cs")
            .bind(token_hash).bind(realm).bind(&client_id).fetch_optional(&mut *conn).await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let session: String = row.try_get("session_id")?;
        let family: String = row.try_get("family_id")?;
        sqlx::query("UPDATE refresh_families SET revoked_at = COALESCE(revoked_at, clock_timestamp()) WHERE id = $1")
            .bind(family).execute(&mut *conn).await?;
        // An offline token ends only its offline session.
        if row.try_get::<bool, _>("offline")? {
            tx.commit().await?;
            return Ok(true);
        }
        sqlx::query("DELETE FROM client_sessions WHERE realm_id = $1 AND client_id = $2 AND user_session_id = $3")
            .bind(realm).bind(client_id).bind(&session).execute(&mut *conn).await?;
        sqlx::query("UPDATE user_sessions SET revoked_at = clock_timestamp() WHERE realm_id = $1 AND id = $2 AND NOT EXISTS (SELECT 1 FROM client_sessions WHERE realm_id = $1 AND user_session_id = $2)")
            .bind(realm).bind(session).execute(&mut *conn).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Introspect an unconsumed refresh token bound to an authenticated client.
    pub async fn introspect_refresh_token(
        &self,
        realm: &str,
        client_identifier: &str,
        client_revision: Option<i64>,
        token_hash: &[u8],
    ) -> Result<Option<RefreshIntrospection>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let client_id =
            authenticated_client(tx.connection(), realm, client_identifier, client_revision)
                .await?;
        if token_hash.len() != 32 {
            tx.commit().await?;
            return Ok(None);
        }
        let row = sqlx::query("SELECT us.realm_id, us.user_id, u.username, us.id AS session_id, c.id AS client_id, c.client_id AS client_identifier, floor(EXTRACT(EPOCH FROM us.created_at))::bigint AS auth_time, f.scope, floor(EXTRACT(EPOCH FROM f.expires_at))::bigint AS expires_at FROM refresh_tokens t JOIN refresh_families f ON f.id = t.family_id JOIN user_sessions us ON us.realm_id = f.realm_id AND us.id = f.user_session_id JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id JOIN realms r ON r.id = us.realm_id JOIN clients c ON c.realm_id = f.realm_id AND c.id = f.client_id JOIN client_sessions cs ON cs.realm_id = us.realm_id AND cs.user_session_id = us.id AND cs.client_id = c.id WHERE t.token_hash = $1 AND f.realm_id = $2 AND f.client_id = $3 AND t.consumed_at IS NULL AND t.generation = f.generation AND f.revoked_at IS NULL AND f.expires_at > clock_timestamp() AND us.revoked_at IS NULL AND us.expires_at > clock_timestamp() AND r.enabled AND u.enabled AND c.enabled")
            .bind(token_hash).bind(realm).bind(client_id).fetch_optional(tx.connection()).await?;
        let result = match row {
            None => None,
            Some(row) => Some(RefreshIntrospection {
                grant: RefreshGrant {
                    expires_at: row.try_get("expires_at")?,
                    session: active_session_row(&row)?,
                    scope: row.try_get("scope")?,
                },
                expires_at: row.try_get("expires_at")?,
            }),
        };
        tx.commit().await?;
        Ok(result)
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
