//! User administration within a realm, audited in the master realm.

use sqlx::Row;
use sqlx::postgres::PgRow;

use crate::{Actor, Storage, StorageError, audit};

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

/// Outcome of updating a user.
pub enum UserUpdate {
    /// The user was updated.
    Updated,
    /// No user has this identifier.
    NotFound,
    /// Another user in the realm has this email.
    EmailExists,
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

/// Filters for listing and counting users. Text filters are lowercase SQL
/// `LIKE` patterns with `\` as the escape character; every filter present
/// must hold.
#[derive(Default)]
pub struct UserQuery<'a> {
    /// Matches the username, email, first name or last name.
    pub search: Option<&'a str>,
    /// Matches the username.
    pub username: Option<&'a str>,
    /// Matches the email.
    pub email: Option<&'a str>,
    /// Matches the first name.
    pub first_name: Option<&'a str>,
    /// Matches the last name.
    pub last_name: Option<&'a str>,
    /// Matches the enabled state.
    pub enabled: Option<bool>,
    /// Matches whether the email is verified.
    pub email_verified: Option<bool>,
}

/// Conditions on `$2`..`$8` for a [`UserQuery`], after the realm in `$1`;
/// service accounts are never listed.
const USER_QUERY_CONDITIONS: &str = "realm_id = $1 AND service_account_client_id IS NULL AND ($2::text IS NULL OR username_normalized LIKE $2 ESCAPE '\\' OR email_normalized LIKE $2 ESCAPE '\\' OR lower(first_name) LIKE $2 ESCAPE '\\' OR lower(last_name) LIKE $2 ESCAPE '\\') AND ($3::text IS NULL OR username_normalized LIKE $3 ESCAPE '\\') AND ($4::text IS NULL OR email_normalized LIKE $4 ESCAPE '\\') AND ($5::text IS NULL OR lower(first_name) LIKE $5 ESCAPE '\\') AND ($6::text IS NULL OR lower(last_name) LIKE $6 ESCAPE '\\') AND ($7::boolean IS NULL OR enabled = $7) AND ($8::boolean IS NULL OR email_verified = $8)";

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

impl Storage {
    /// Creates a user unless its username or email is already taken.
    pub async fn create_user(
        &self,
        realm_id: &str,
        user_id: &str,
        user: &NewUser<'_>,
        actor: &Actor,
    ) -> Result<UserCreation, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        // New users also get the realm's default required actions.
        let created: Option<String> = sqlx::query_scalar("INSERT INTO users (realm_id, id, username, username_normalized, email, email_normalized, email_verified, first_name, last_name, enabled, required_actions) VALUES ($1, $2, $3, $3, $4, $4, $5, $6, $7, $8, ARRAY(SELECT DISTINCT action FROM unnest($9::text[] || ARRAY(SELECT alias FROM required_action_settings WHERE realm_id = $1 AND default_action AND enabled)) AS action ORDER BY action)) ON CONFLICT DO NOTHING RETURNING id")
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
        audit(conn, actor, "user_created").await?;
        tx.commit().await?;
        Ok(UserCreation::Created)
    }

    /// Replaces a user's profile, enabled state and required actions; the
    /// username stays, since the reference keeps it read-only.
    pub async fn update_user(
        &self,
        realm_id: &str,
        user_id: &str,
        user: &NewUser<'_>,
        actor: &Actor,
    ) -> Result<UserUpdate, StorageError> {
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
            return Ok(UserUpdate::NotFound);
        }
        let email_taken: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND email_normalized = $2 AND id <> $3)")
            .bind(realm_id).bind(user.email).bind(user_id).fetch_one(&mut *conn).await?;
        if email_taken {
            tx.commit().await?;
            return Ok(UserUpdate::EmailExists);
        }
        sqlx::query("UPDATE users SET email = $3, email_normalized = $3, email_verified = $4, first_name = $5, last_name = $6, enabled = $7, required_actions = $8 WHERE realm_id = $1 AND id = $2")
            .bind(realm_id).bind(user_id).bind(user.email).bind(user.email_verified)
            .bind(user.first_name).bind(user.last_name).bind(user.enabled).bind(user.required_actions)
            .execute(&mut *conn).await?;
        audit(conn, actor, "user_updated").await?;
        tx.commit().await?;
        Ok(UserUpdate::Updated)
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

    /// Lists users matching a query, ordered by username.
    pub async fn search_users(
        &self,
        realm_id: &str,
        query: &UserQuery<'_>,
        first: i64,
        max: i64,
    ) -> Result<Vec<UserRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query(&format!("SELECT {USER_COLUMNS} FROM users WHERE {USER_QUERY_CONDITIONS} ORDER BY username_normalized OFFSET $9 LIMIT $10"))
            .bind(realm_id).bind(query.search).bind(query.username).bind(query.email).bind(query.first_name).bind(query.last_name).bind(query.enabled).bind(query.email_verified)
            .bind(first).bind(max)
            .fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter().map(user_row).collect()
    }

    /// Counts users matching a query.
    pub async fn count_users(
        &self,
        realm_id: &str,
        query: &UserQuery<'_>,
    ) -> Result<i64, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let count = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM users WHERE {USER_QUERY_CONDITIONS}"
        ))
        .bind(realm_id)
        .bind(query.search)
        .bind(query.username)
        .bind(query.email)
        .bind(query.first_name)
        .bind(query.last_name)
        .bind(query.enabled)
        .bind(query.email_verified)
        .fetch_one(tx.connection())
        .await?;
        tx.commit().await?;
        Ok(count)
    }

    /// Replaces a user's password hash; returns false if the user is missing.
    /// Pending login challenges for the old credential are removed with it.
    /// A temporary password requires UPDATE_PASSWORD at the next login; a
    /// permanent one clears that action.
    pub async fn reset_password(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
        password_phc: &[u8],
        temporary: bool,
        actor: &Actor,
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
        sqlx::query("UPDATE users SET required_actions = CASE WHEN $3 THEN array_append(array_remove(required_actions, 'UPDATE_PASSWORD'), 'UPDATE_PASSWORD') ELSE array_remove(required_actions, 'UPDATE_PASSWORD') END WHERE realm_id = $1 AND id = $2")
            .bind(realm_id).bind(user_id).bind(temporary).execute(&mut *conn).await?;
        audit(conn, actor, "user_password_reset").await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Deletes a user with its credentials and sessions; false if missing.
    pub async fn delete_user(
        &self,
        realm_id: &str,
        user_id: &str,
        actor: &Actor,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let deleted = sqlx::query("DELETE FROM users WHERE realm_id = $1 AND id = $2 AND service_account_client_id IS NULL")
            .bind(realm_id).bind(user_id).execute(&mut *conn).await?.rows_affected();
        if deleted == 0 {
            tx.commit().await?;
            return Ok(false);
        }
        audit(conn, actor, "user_deleted").await?;
        tx.commit().await?;
        Ok(true)
    }
}
