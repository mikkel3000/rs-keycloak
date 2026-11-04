//! User administration within a realm, audited in the master realm.

use sqlx::postgres::PgRow;
use sqlx::{PgConnection, Row};

use crate::realm_admin::MASTER_REALM;
use crate::{Storage, StorageError};

/// Profile values for a new user; callers normalize and validate them first.
pub struct NewUser<'a> {
    /// Lowercased username.
    pub username: &'a str,
    /// Lowercased email, if any.
    pub email: Option<&'a str>,
    /// Whether the email address is verified.
    pub email_verified: bool,
    /// Given name.
    pub first_name: Option<&'a str>,
    /// Family name.
    pub last_name: Option<&'a str>,
    /// Whether the user may sign in.
    pub enabled: bool,
    /// Actions the user must complete at the next login.
    pub required_actions: &'a [String],
}

/// A stored user with the fields of the admin representation.
pub struct UserRecord {
    /// User identifier.
    pub id: String,
    /// Lowercased username.
    pub username: String,
    /// Lowercased email, if any.
    pub email: Option<String>,
    /// Whether the email address is verified.
    pub email_verified: bool,
    /// Given name.
    pub first_name: Option<String>,
    /// Family name.
    pub last_name: Option<String>,
    /// Whether the user may sign in.
    pub enabled: bool,
    /// Creation time in Unix milliseconds.
    pub created_timestamp: i64,
    /// Actions the user must complete at the next login.
    pub required_actions: Vec<String>,
    /// Whether the user has an OTP credential.
    pub totp: bool,
}

/// Outcome of creating a user.
pub enum UserCreation {
    /// The user was created.
    Created,
    /// Another user in the realm has this username.
    UsernameExists,
    /// Another user in the realm has this email.
    EmailExists,
}

/// Username filter for a user search.
pub enum UsernameFilter<'a> {
    /// Matches every user.
    Any,
    /// Matches the lowercased username exactly.
    Exact(&'a str),
    /// Matches usernames containing the lowercased value.
    Contains(&'a str),
}

pub(crate) const USER_COLUMNS: &str = "id, username, email, email_verified, first_name, last_name, enabled, (floor(EXTRACT(EPOCH FROM created_at) * 1000))::bigint AS created_timestamp, required_actions, EXISTS (SELECT 1 FROM credentials c WHERE c.realm_id = users.realm_id AND c.user_id = users.id AND c.credential_type = 'otp') AS totp";

pub(crate) fn user_row(row: &PgRow) -> Result<UserRecord, StorageError> {
    Ok(UserRecord {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        email: row.try_get("email")?,
        email_verified: row.try_get("email_verified")?,
        first_name: row.try_get("first_name")?,
        last_name: row.try_get("last_name")?,
        enabled: row.try_get("enabled")?,
        created_timestamp: row.try_get("created_timestamp")?,
        required_actions: row.try_get("required_actions")?,
        totp: row.try_get("totp")?,
    })
}

async fn audit(
    connection: &mut PgConnection,
    actor_user_id: &str,
    event_type: &str,
) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT INTO audit_events (realm_id, actor_user_id, event_type) VALUES ($1, $2, $3)",
    )
    .bind(MASTER_REALM)
    .bind(actor_user_id)
    .bind(event_type)
    .execute(connection)
    .await?;
    Ok(())
}

impl Storage {
    /// Creates a user unless its username or email is already taken.
    pub async fn create_user(
        &self,
        realm_id: &str,
        user_id: &str,
        user: &NewUser<'_>,
        actor_user_id: &str,
    ) -> Result<UserCreation, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let created: Option<String> = sqlx::query_scalar("INSERT INTO users (realm_id, id, username, username_normalized, email, email_normalized, email_verified, first_name, last_name, enabled, required_actions) VALUES ($1, $2, $3, $3, $4, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING RETURNING id")
            .bind(realm_id).bind(user_id).bind(user.username).bind(user.email).bind(user.email_verified)
            .bind(user.first_name).bind(user.last_name).bind(user.enabled).bind(user.required_actions).fetch_optional(&mut *conn).await?;
        if created.is_none() {
            let username_taken: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND username_normalized = $2)")
                .bind(realm_id).bind(user.username).fetch_one(&mut *conn).await?;
            tx.commit().await?;
            return Ok(if username_taken {
                UserCreation::UsernameExists
            } else {
                UserCreation::EmailExists
            });
        }
        audit(conn, actor_user_id, "user_created").await?;
        tx.commit().await?;
        Ok(UserCreation::Created)
    }

    /// Reads one user by identifier.
    pub async fn user(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let row = sqlx::query(&format!(
            "SELECT {USER_COLUMNS} FROM users WHERE realm_id = $1 AND id = $2"
        ))
        .bind(realm_id)
        .bind(user_id)
        .fetch_optional(tx.connection())
        .await?;
        tx.commit().await?;
        row.as_ref().map(user_row).transpose()
    }

    /// Lists users ordered by username; service-account users are excluded.
    pub async fn search_users(
        &self,
        realm_id: &str,
        filter: UsernameFilter<'_>,
        first: i64,
        max: i64,
    ) -> Result<Vec<UserRecord>, StorageError> {
        let base = format!(
            "SELECT {USER_COLUMNS} FROM users WHERE realm_id = $1 AND service_account_client_id IS NULL"
        );
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let rows = match filter {
            UsernameFilter::Any => {
                sqlx::query(&format!("{base} ORDER BY username_normalized OFFSET $2 LIMIT $3"))
                    .bind(realm_id)
                    .bind(first)
                    .bind(max)
                    .fetch_all(conn)
                    .await?
            }
            UsernameFilter::Exact(value) => sqlx::query(&format!(
                "{base} AND username_normalized = $2 ORDER BY username_normalized OFFSET $3 LIMIT $4"
            ))
            .bind(realm_id)
            .bind(value)
            .bind(first)
            .bind(max)
            .fetch_all(conn)
            .await?,
            UsernameFilter::Contains(value) => sqlx::query(&format!(
                "{base} AND strpos(username_normalized, $2) > 0 ORDER BY username_normalized OFFSET $3 LIMIT $4"
            ))
            .bind(realm_id)
            .bind(value)
            .bind(first)
            .bind(max)
            .fetch_all(conn)
            .await?,
        };
        tx.commit().await?;
        rows.iter().map(user_row).collect()
    }

    /// Counts the realm's users, excluding service-account users.
    pub async fn count_users(&self, realm_id: &str) -> Result<i64, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let count = sqlx::query_scalar(
            "SELECT count(*) FROM users WHERE realm_id = $1 AND service_account_client_id IS NULL",
        )
        .bind(realm_id)
        .fetch_one(tx.connection())
        .await?;
        tx.commit().await?;
        Ok(count)
    }

    /// Replaces a user's password hash; returns false if the user is missing.
    /// Pending login challenges for the old credential are removed with it.
    pub async fn reset_password(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
        password_phc: &[u8],
        actor_user_id: &str,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id = $2 FOR UPDATE)",
        )
        .bind(realm_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;
        if !exists {
            tx.commit().await?;
            return Ok(false);
        }
        sqlx::query("DELETE FROM credentials WHERE realm_id = $1 AND user_id = $2 AND credential_type = 'password'")
            .bind(realm_id).bind(user_id).execute(&mut *conn).await?;
        sqlx::query("INSERT INTO credentials (realm_id, id, user_id, credential_type, secret_data) VALUES ($1, $2, $3, 'password', $4)")
            .bind(realm_id).bind(credential_id).bind(user_id).bind(password_phc).execute(&mut *conn).await?;
        audit(conn, actor_user_id, "user_password_reset").await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Deletes a user with its credentials and sessions; false if missing.
    pub async fn delete_user(
        &self,
        realm_id: &str,
        user_id: &str,
        actor_user_id: &str,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let deleted = sqlx::query("DELETE FROM users WHERE realm_id = $1 AND id = $2 AND service_account_client_id IS NULL")
            .bind(realm_id).bind(user_id).execute(&mut *conn).await?.rows_affected();
        if deleted == 0 {
            tx.commit().await?;
            return Ok(false);
        }
        audit(conn, actor_user_id, "user_deleted").await?;
        tx.commit().await?;
        Ok(true)
    }
}
