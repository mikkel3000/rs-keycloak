//! Login steps after the password: OTP verification, then the user's required
//! actions (CONFIGURE_TOTP, UPDATE_PASSWORD), in the reference order. A
//! session stays pending, without codes or SSO, until every step has passed.

use sqlx::{PgConnection, Row};

use crate::account::account_conflicts;
use crate::{AccountChange, AccountConflicts, Actor, Storage, StorageError, audit};

/// What a freshly authenticated session still needs before a code is issued.
pub enum LoginStep {
    /// Every step has passed.
    Complete,
    /// The user must enter a code for this OTP credential.
    VerifyTotp {
        /// The credential to check the code against.
        credential: OtpCredential,
        /// The signed-in user's username, which the code page shows.
        username: String,
    },
    /// The user must set up TOTP.
    ConfigureTotp,
    /// The user must choose a new password.
    UpdatePassword,
    /// The user must review their profile; carries the current values.
    UpdateProfile {
        /// The stored username.
        username: String,
        /// The stored name and email.
        profile: Profile,
    },
    /// The user must verify their email address.
    VerifyEmail {
        /// User whose address is unverified.
        user_id: String,
        /// Address to send the link to.
        email: String,
    },
}

/// The profile fields a user reviews at login.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Profile {
    /// Given name.
    pub first_name: Option<String>,
    /// Family name.
    pub last_name: Option<String>,
    /// Email address.
    pub email: Option<String>,
}

/// Outcome of a profile update at login.
pub enum ProfileUpdate {
    /// The profile was saved.
    Updated,
    /// Nothing was saved: the username or email collides, or the caller
    /// only asked for the check.
    Checked(AccountConflicts),
    /// The session is no longer waiting on this step.
    NotPending,
}

/// A user's OTP credential with its sealed seed.
pub struct OtpCredential {
    /// Credential identifier, part of the sealing context.
    pub id: String,
    /// Nonce and ciphertext of the seed.
    pub sealed: Vec<u8>,
    /// Identifier of the sealing key.
    pub key_id: String,
    /// Last accepted time step; later codes only.
    pub last_step: Option<i64>,
}

/// A credential as listed by the admin API.
pub struct CredentialRecord {
    /// Credential identifier.
    pub id: String,
    /// `password` or `otp`.
    pub credential_type: String,
    /// Optional user-facing label.
    pub user_label: Option<String>,
    /// Creation time in Unix milliseconds.
    pub created: i64,
}

/// Clears the pending flag once the user has no required actions left.
async fn settle_session(
    connection: &mut PgConnection,
    realm_id: &str,
    session_id: &str,
) -> Result<(), StorageError> {
    sqlx::query("UPDATE user_sessions us SET steps_pending = cardinality(rs_active_required_actions(u.realm_id, u.required_actions)) > 0 FROM users u WHERE u.realm_id = us.realm_id AND u.id = us.user_id AND us.realm_id = $1 AND us.id = $2")
        .bind(realm_id)
        .bind(session_id)
        .execute(connection)
        .await?;
    Ok(())
}

/// Removes a completed required action from the session's user.
async fn complete_action(
    connection: &mut PgConnection,
    realm_id: &str,
    user_id: &str,
    action: &str,
) -> Result<(), StorageError> {
    sqlx::query("UPDATE users SET required_actions = array_remove(required_actions, $3) WHERE realm_id = $1 AND id = $2")
        .bind(realm_id)
        .bind(user_id)
        .bind(action)
        .execute(connection)
        .await?;
    Ok(())
}

/// Saves name and email, returning false if another user has the email. A
/// changed email loses its verified flag and, where the realm verifies
/// email, adds VERIFY_EMAIL. `complete_action` also clears UPDATE_PROFILE.
pub(crate) async fn save_profile(
    connection: &mut PgConnection,
    realm_id: &str,
    user_id: &str,
    profile: &Profile,
    complete_action: bool,
) -> Result<bool, StorageError> {
    let email = profile.email.as_deref().map(str::to_lowercase);
    let taken: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id <> $2 AND email_normalized = $3)")
        .bind(realm_id).bind(user_id).bind(&email).fetch_one(&mut *connection).await?;
    if taken {
        return Ok(false);
    }
    sqlx::query("UPDATE users u SET first_name = $3, last_name = $4, email_verified = u.email_verified AND u.email_normalized IS NOT DISTINCT FROM $5, required_actions = array_remove(CASE WHEN r.verify_email AND u.email_normalized IS DISTINCT FROM $5 AND $5 IS NOT NULL AND NOT ('VERIFY_EMAIL' = ANY(u.required_actions)) THEN array_append(u.required_actions, 'VERIFY_EMAIL') ELSE u.required_actions END, CASE WHEN $6 THEN 'UPDATE_PROFILE' END), email = $5, email_normalized = $5 FROM realms r WHERE r.id = u.realm_id AND u.realm_id = $1 AND u.id = $2")
        .bind(realm_id).bind(user_id).bind(&profile.first_name).bind(&profile.last_name).bind(&email).bind(complete_action)
        .execute(connection).await?;
    Ok(true)
}

/// Locks a pending session and returns its user.
async fn pending_user(
    connection: &mut PgConnection,
    realm_id: &str,
    session_id: &str,
) -> Result<Option<String>, StorageError> {
    Ok(sqlx::query_scalar("SELECT user_id FROM user_sessions WHERE realm_id = $1 AND id = $2 AND steps_pending AND revoked_at IS NULL AND expires_at > clock_timestamp() FOR UPDATE")
        .bind(realm_id).bind(session_id).fetch_optional(connection).await?)
}

/// Whether the user `u` has a required action assigned that the realm has
/// not disabled, as a column named `column`.
fn assigned(alias: &str, column: &str) -> String {
    format!(
        "'{alias}' = ANY(rs_active_required_actions(u.realm_id, u.required_actions)) AS {column}"
    )
}

/// A realm's stored settings for one required action.
pub struct RequiredActionSetting {
    /// Action alias, such as `UPDATE_PASSWORD`.
    pub alias: String,
    /// Whether the action runs at login.
    pub enabled: bool,
    /// Whether new users are given the action.
    pub default_action: bool,
}

impl Storage {
    /// Lists the required actions a realm has changed from the defaults.
    pub async fn required_action_settings(
        &self,
        realm_id: &str,
    ) -> Result<Vec<RequiredActionSetting>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query("SELECT alias, enabled, default_action FROM required_action_settings WHERE realm_id = $1")
            .bind(realm_id).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| {
                Ok(RequiredActionSetting {
                    alias: row.try_get("alias")?,
                    enabled: row.try_get("enabled")?,
                    default_action: row.try_get("default_action")?,
                })
            })
            .collect()
    }

    /// Saves a realm's settings for one required action.
    pub async fn save_required_action(
        &self,
        realm_id: &str,
        setting: &RequiredActionSetting,
        actor: &Actor,
    ) -> Result<(), StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        sqlx::query("INSERT INTO required_action_settings (realm_id, alias, enabled, default_action) VALUES ($1, $2, $3, $4) ON CONFLICT (realm_id, alias) DO UPDATE SET enabled = EXCLUDED.enabled, default_action = EXCLUDED.default_action")
            .bind(realm_id).bind(&setting.alias).bind(setting.enabled).bind(setting.default_action)
            .execute(&mut *conn).await?;
        audit(conn, actor, "required_action_updated").await?;
        tx.commit().await?;
        Ok(())
    }

    /// Returns the next step a session needs: an OTP code first, then the
    /// user's required actions.
    pub async fn login_step(
        &self,
        realm_id: &str,
        session_id: &str,
    ) -> Result<LoginStep, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query(&format!("SELECT us.steps_pending, us.otp_verified, {configure}, {update_password}, {verify_email}, {update_profile}, u.id AS user_id, u.username, u.email, u.first_name, u.last_name, c.id AS credential_id, c.secret_data, c.secret_key_id, c.otp_last_step FROM user_sessions us JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id LEFT JOIN credentials c ON c.realm_id = u.realm_id AND c.user_id = u.id AND c.credential_type = 'otp' WHERE us.realm_id = $1 AND us.id = $2 AND us.revoked_at IS NULL AND us.expires_at > clock_timestamp()",
            configure = assigned("CONFIGURE_TOTP", "configure"),
            update_password = assigned("UPDATE_PASSWORD", "update_password"),
            verify_email = assigned("VERIFY_EMAIL", "verify_email"),
            update_profile = assigned("UPDATE_PROFILE", "update_profile"),
        ))
            .bind(realm_id).bind(session_id).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        let Some(row) = row else {
            return Ok(LoginStep::Complete);
        };
        if !row.try_get::<bool, _>("steps_pending")? {
            return Ok(LoginStep::Complete);
        }
        let configure: bool = row.try_get("configure")?;
        if let Some(id) = row.try_get::<Option<String>, _>("credential_id")?
            && !configure
            && !row.try_get::<bool, _>("otp_verified")?
        {
            return Ok(LoginStep::VerifyTotp {
                credential: OtpCredential {
                    id,
                    sealed: row.try_get("secret_data")?,
                    key_id: row.try_get("secret_key_id")?,
                    last_step: row.try_get("otp_last_step")?,
                },
                username: row.try_get("username")?,
            });
        }
        if configure {
            return Ok(LoginStep::ConfigureTotp);
        }
        if row.try_get::<bool, _>("update_password")? {
            return Ok(LoginStep::UpdatePassword);
        }
        if row.try_get::<bool, _>("update_profile")? {
            return Ok(LoginStep::UpdateProfile {
                username: row.try_get("username")?,
                profile: Profile {
                    first_name: row.try_get("first_name")?,
                    last_name: row.try_get("last_name")?,
                    email: row.try_get("email")?,
                },
            });
        }
        if row.try_get::<bool, _>("verify_email")?
            && let Some(email) = row.try_get::<Option<String>, _>("email")?
        {
            return Ok(LoginStep::VerifyEmail {
                user_id: row.try_get("user_id")?,
                email,
            });
        }
        // Nothing is left: clear the flag so the session can receive a code.
        let mut tx = self.begin_request(true).await?;
        settle_session(tx.connection(), realm_id, session_id).await?;
        tx.commit().await?;
        Ok(LoginStep::Complete)
    }

    /// Records an accepted code's step, unless a concurrent request already
    /// used this or a later step, and settles the session.
    pub async fn accept_otp(
        &self,
        realm_id: &str,
        session_id: &str,
        credential_id: &str,
        step: i64,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let accepted = sqlx::query("UPDATE credentials SET otp_last_step = $3 WHERE realm_id = $1 AND id = $2 AND credential_type = 'otp' AND (otp_last_step IS NULL OR otp_last_step < $3)")
            .bind(realm_id).bind(credential_id).bind(step).execute(&mut *conn).await?.rows_affected() == 1;
        if accepted {
            sqlx::query(
                "UPDATE user_sessions SET otp_verified = true WHERE realm_id = $1 AND id = $2",
            )
            .bind(realm_id)
            .bind(session_id)
            .execute(&mut *conn)
            .await?;
            settle_session(conn, realm_id, session_id).await?;
        }
        tx.commit().await?;
        Ok(accepted)
    }

    /// Keeps `sealed` as a live request's TOTP setup secret unless it
    /// already has one, and returns the one it keeps.
    pub async fn keep_totp_setup_secret(
        &self,
        realm_id: &str,
        request_id: &str,
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>, StorageError> {
        if sealed.is_empty() || sealed.len() > 256 {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(true).await?;
        let kept: Option<Vec<u8>> = sqlx::query_scalar("UPDATE authorization_requests SET totp_setup_secret = COALESCE(totp_setup_secret, $3) WHERE realm_id = $1 AND id = $2 AND consumed_at IS NULL AND expires_at > clock_timestamp() RETURNING totp_setup_secret")
            .bind(realm_id).bind(request_id).bind(sealed)
            .fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        Ok(kept)
    }

    /// Stores a newly set-up OTP credential, replacing any earlier one,
    /// completes CONFIGURE_TOTP and settles the session.
    #[allow(clippy::too_many_arguments)]
    pub async fn configure_otp(
        &self,
        realm_id: &str,
        session_id: &str,
        credential_id: &str,
        sealed_seed: &[u8],
        key_id: &str,
        label: Option<&str>,
        step: i64,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let Some(user) = pending_user(conn, realm_id, session_id).await? else {
            tx.commit().await?;
            return Ok(false);
        };
        sqlx::query("DELETE FROM credentials WHERE realm_id = $1 AND user_id = $2 AND credential_type = 'otp'")
            .bind(realm_id).bind(&user).execute(&mut *conn).await?;
        sqlx::query("INSERT INTO credentials (realm_id, id, user_id, credential_type, secret_data, secret_key_id, user_label, otp_last_step) VALUES ($1, $2, $3, 'otp', $4, $5, $6, $7)")
            .bind(realm_id).bind(credential_id).bind(&user).bind(sealed_seed).bind(key_id).bind(label).bind(step)
            .execute(&mut *conn).await?;
        sqlx::query("UPDATE user_sessions SET otp_verified = true WHERE realm_id = $1 AND id = $2")
            .bind(realm_id)
            .bind(session_id)
            .execute(&mut *conn)
            .await?;
        complete_action(conn, realm_id, &user, "CONFIGURE_TOTP").await?;
        settle_session(conn, realm_id, session_id).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Replaces the password of a pending session's user, completes
    /// UPDATE_PASSWORD and settles the session.
    pub async fn update_password_step(
        &self,
        realm_id: &str,
        session_id: &str,
        credential_id: &str,
        password_phc: &[u8],
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let Some(user) = pending_user(conn, realm_id, session_id).await? else {
            tx.commit().await?;
            return Ok(false);
        };
        sqlx::query("DELETE FROM credentials WHERE realm_id = $1 AND user_id = $2 AND credential_type = 'password'")
            .bind(realm_id).bind(&user).execute(&mut *conn).await?;
        sqlx::query("INSERT INTO credentials (realm_id, id, user_id, credential_type, secret_data) VALUES ($1, $2, $3, 'password', $4)")
            .bind(realm_id).bind(credential_id).bind(&user).bind(password_phc).execute(&mut *conn).await?;
        complete_action(conn, realm_id, &user, "UPDATE_PASSWORD").await?;
        settle_session(conn, realm_id, session_id).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Lists a user's credentials, or `None` if the user is missing.
    pub async fn user_credentials(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Option<Vec<CredentialRecord>>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id = $2)",
        )
        .bind(realm_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;
        let credentials = if exists {
            let rows = sqlx::query("SELECT id, credential_type, user_label, (floor(EXTRACT(EPOCH FROM created_at) * 1000))::bigint AS created FROM credentials WHERE realm_id = $1 AND user_id = $2 ORDER BY credential_type DESC, created_at")
                .bind(realm_id).bind(user_id).fetch_all(&mut *conn).await?;
            Some(
                rows.iter()
                    .map(|row| {
                        Ok(CredentialRecord {
                            id: row.try_get("id")?,
                            credential_type: row.try_get("credential_type")?,
                            user_label: row.try_get("user_label")?,
                            created: row.try_get("created")?,
                        })
                    })
                    .collect::<Result<_, StorageError>>()?,
            )
        } else {
            None
        };
        tx.commit().await?;
        Ok(credentials)
    }

    /// Deletes one of a user's credentials; false if it does not exist.
    pub async fn delete_credential(
        &self,
        realm_id: &str,
        user_id: &str,
        credential_id: &str,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let deleted =
            sqlx::query("DELETE FROM credentials WHERE realm_id = $1 AND user_id = $2 AND id = $3")
                .bind(realm_id)
                .bind(user_id)
                .bind(credential_id)
                .execute(tx.connection())
                .await?
                .rows_affected();
        tx.commit().await?;
        Ok(deleted == 1)
    }

    /// Checks a reviewed profile against other users like an account
    /// update; if nothing collides and `apply` is set, saves it with the
    /// username, completes UPDATE_PROFILE and settles the session. A changed
    /// email becomes unverified, and in a realm that verifies email the user
    /// must then verify it.
    pub async fn update_profile_step(
        &self,
        realm_id: &str,
        session_id: &str,
        change: &AccountChange<'_>,
        apply: bool,
    ) -> Result<ProfileUpdate, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let Some(user) = pending_user(conn, realm_id, session_id).await? else {
            tx.commit().await?;
            return Ok(ProfileUpdate::NotPending);
        };
        let conflicts = account_conflicts(conn, realm_id, &user, change).await?;
        if !apply || conflicts.any() {
            tx.commit().await?;
            return Ok(ProfileUpdate::Checked(conflicts));
        }
        sqlx::query("UPDATE users SET username = $3, username_normalized = $3 WHERE realm_id = $1 AND id = $2")
            .bind(realm_id)
            .bind(&user)
            .bind(change.saved_username.to_lowercase())
            .execute(&mut *conn)
            .await?;
        if !save_profile(conn, realm_id, &user, &change.profile, true).await? {
            return Err(StorageError::InvalidInput);
        }
        settle_session(conn, realm_id, session_id).await?;
        tx.commit().await?;
        Ok(ProfileUpdate::Updated)
    }
}
