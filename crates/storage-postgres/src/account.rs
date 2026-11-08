//! A user's own account: authorization, profile and sessions.

use sqlx::{PgConnection, Row};

use crate::login_steps::{Profile, save_profile};
use crate::{Storage, StorageError};

/// One of the user's active sessions.
pub struct AccountSession {
    /// Session identifier.
    pub id: String,
    /// Start time in Unix seconds.
    pub started: i64,
    /// Expiry time in Unix seconds.
    pub expires: i64,
    /// Public identifiers of the clients in the session, sorted.
    pub clients: Vec<String>,
}

/// A client the user uses, as the account console lists it.
pub struct AccountApplication {
    /// Public client identifier.
    pub client_identifier: String,
    /// Whether users must consent before the client receives a code.
    pub consent_required: bool,
    /// Root URL that the base URL resolves against.
    pub root_url: Option<String>,
    /// The client's home page, possibly relative to the root URL.
    pub base_url: Option<String>,
    /// Whether the caller's current session includes the client.
    pub in_use: bool,
    /// Whether the user has a live offline token for the client.
    pub offline: bool,
    /// Name shown to users, if set.
    pub name: Option<String>,
    /// Description shown to users, if set.
    pub description: Option<String>,
}

/// A change to the user's own account.
pub struct AccountChange<'a> {
    /// The username uniqueness is checked for: the requested one, even
    /// when it may not be changed, as the reference validates it.
    pub checked_username: &'a str,
    /// The username stored.
    pub saved_username: &'a str,
    /// Name and email to store.
    pub profile: Profile,
    /// The chosen locale: `None` keeps it, `Some(None)` removes it.
    pub locale: Option<Option<&'a str>>,
    /// Whether the realm uses the email as username, which adds a check
    /// that no other user has the email.
    pub email_as_username: bool,
}

/// What an account change collides with; each is the reference's error.
#[derive(Debug, Default)]
pub struct AccountConflicts {
    /// Another user has the username.
    pub username_taken: bool,
    /// The username looks like an email that another user has.
    pub username_is_email: bool,
    /// The email changed and another user has it.
    pub email_taken: bool,
    /// The email changed and is another user's username.
    pub email_is_username: bool,
    /// The realm uses the email as username and another user has it.
    pub email_as_username: bool,
}

impl AccountConflicts {
    /// Whether anything collides.
    pub fn any(&self) -> bool {
        self.username_taken
            || self.username_is_email
            || self.email_taken
            || self.email_is_username
            || self.email_as_username
    }
}

/// Checks a user's own username and email change against other users, as
/// the reference's user profile validators do.
pub(crate) async fn account_conflicts(
    connection: &mut PgConnection,
    realm_id: &str,
    user_id: &str,
    change: &AccountChange<'_>,
) -> Result<AccountConflicts, StorageError> {
    let username = change.checked_username.to_lowercase();
    let email = change.profile.email.as_deref().map(str::to_lowercase);
    let row = sqlx::query("SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id <> $2 AND username_normalized = $3) AS username_taken, EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id <> $2 AND email_normalized = $3) AS username_is_email, EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id <> $2 AND email_normalized = $4) AS email_taken, EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id <> $2 AND username_normalized = $4) AS email_is_username, EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id = $2 AND email_normalized IS NOT DISTINCT FROM $4) AS email_kept, r.login_with_email_allowed, r.duplicate_emails_allowed FROM realms r WHERE r.id = $1")
        .bind(realm_id).bind(user_id).bind(&username).bind(&email).fetch_one(connection).await?;
    let username_taken: bool = row.try_get("username_taken")?;
    let email_kept: bool = row.try_get("email_kept")?;
    // Email checks run without duplicate emails, and the checks across
    // usernames and emails with email login, as the validators do.
    let email_login: bool = row.try_get("login_with_email_allowed")?;
    let unique: bool = !row.try_get::<bool, _>("duplicate_emails_allowed")?;
    let email_taken = unique && row.try_get::<bool, _>("email_taken")?;
    Ok(AccountConflicts {
        username_taken,
        username_is_email: !username_taken
            && email_login
            && username.find('@').is_some_and(|at| at > 0)
            && row.try_get::<bool, _>("username_is_email")?,
        email_taken: !email_kept && email_taken,
        email_is_username: !email_kept
            && unique
            && email_login
            && !email_taken
            && row.try_get::<bool, _>("email_is_username")?,
        email_as_username: change.email_as_username && email_taken,
    })
}

impl Storage {
    /// Lists the clients of the user's current session, and those the user
    /// has consented to or holds offline tokens for.
    pub async fn account_applications(
        &self,
        realm_id: &str,
        user_id: &str,
        session_id: &str,
    ) -> Result<Vec<AccountApplication>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query("SELECT * FROM (SELECT c.client_id, c.consent_required, c.root_url, c.base_url, c.name, c.description, EXISTS (SELECT 1 FROM client_sessions cs WHERE cs.realm_id = c.realm_id AND cs.client_id = c.id AND cs.user_session_id = $3) AS in_use, EXISTS (SELECT 1 FROM refresh_families f JOIN user_sessions us ON us.realm_id = f.realm_id AND us.id = f.user_session_id WHERE f.realm_id = c.realm_id AND f.client_id = c.id AND us.user_id = $2 AND f.offline AND f.revoked_at IS NULL AND f.expires_at > clock_timestamp()) AS offline, EXISTS (SELECT 1 FROM user_consents uc WHERE uc.realm_id = c.realm_id AND uc.client_id = c.id AND uc.user_id = $2) AS consented FROM clients c WHERE c.realm_id = $1 AND c.enabled) apps WHERE in_use OR offline OR consented ORDER BY client_id")
            .bind(realm_id).bind(user_id).bind(session_id).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| {
                Ok(AccountApplication {
                    client_identifier: row.try_get("client_id")?,
                    consent_required: row.try_get("consent_required")?,
                    root_url: row.try_get("root_url")?,
                    base_url: row.try_get("base_url")?,
                    in_use: row.try_get("in_use")?,
                    offline: row.try_get("offline")?,
                    name: row.try_get("name")?,
                    description: row.try_get("description")?,
                })
            })
            .collect()
    }

    /// Checks the user's own username and email against other users, and
    /// saves the change only if nothing collides and `apply` is set.
    pub async fn update_account(
        &self,
        realm_id: &str,
        user_id: &str,
        change: &AccountChange<'_>,
        apply: bool,
    ) -> Result<AccountConflicts, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let conflicts = account_conflicts(conn, realm_id, user_id, change).await?;
        if !apply || conflicts.any() {
            tx.commit().await?;
            return Ok(conflicts);
        }
        sqlx::query("UPDATE users SET username = $3, username_normalized = $3, locale = CASE WHEN $4 THEN $5 ELSE locale END WHERE realm_id = $1 AND id = $2")
            .bind(realm_id).bind(user_id).bind(change.saved_username.to_lowercase())
            .bind(change.locale.is_some()).bind(change.locale.flatten())
            .execute(&mut *conn).await?;
        if !save_profile(conn, realm_id, user_id, &change.profile, false).await? {
            return Err(StorageError::InvalidInput);
        }
        tx.commit().await?;
        Ok(conflicts)
    }

    /// Lists the user's active, fully authenticated sessions, newest first.
    pub async fn account_sessions(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Vec<AccountSession>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query("SELECT us.id, floor(EXTRACT(EPOCH FROM us.created_at))::bigint AS started, floor(EXTRACT(EPOCH FROM us.expires_at))::bigint AS expires, ARRAY(SELECT c.client_id FROM client_sessions cs JOIN clients c ON c.realm_id = cs.realm_id AND c.id = cs.client_id WHERE cs.realm_id = us.realm_id AND cs.user_session_id = us.id ORDER BY c.client_id) AS clients FROM user_sessions us WHERE us.realm_id = $1 AND us.user_id = $2 AND us.revoked_at IS NULL AND NOT us.steps_pending AND us.expires_at > clock_timestamp() ORDER BY us.created_at DESC")
            .bind(realm_id).bind(user_id).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| {
                Ok(AccountSession {
                    id: row.try_get("id")?,
                    started: row.try_get("started")?,
                    expires: row.try_get("expires")?,
                    clients: row.try_get("clients")?,
                })
            })
            .collect()
    }
}
