//! TOTP second factor: sealed seeds, setup, verification and admin listing.

use sqlx::{PgConnection, Row};

use crate::{Storage, StorageError};

/// What a freshly authenticated session still needs before a code is issued.
pub enum MfaStep {
    /// No second factor is pending.
    Complete,
    /// The user must set up TOTP first.
    ConfigureTotp,
    /// The user must enter a code for this OTP credential.
    VerifyTotp(OtpCredential),
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

/// Marks a pending session as fully authenticated.
async fn complete_session(
    connection: &mut PgConnection,
    realm_id: &str,
    session_id: &str,
) -> Result<(), StorageError> {
    sqlx::query("UPDATE user_sessions SET mfa_pending = false WHERE realm_id = $1 AND id = $2")
        .bind(realm_id)
        .bind(session_id)
        .execute(connection)
        .await?;
    Ok(())
}

impl Storage {
    /// Returns the second-factor step a session still needs.
    pub async fn mfa_step(
        &self,
        realm_id: &str,
        session_id: &str,
    ) -> Result<MfaStep, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query("SELECT us.mfa_pending, 'CONFIGURE_TOTP' = ANY(u.required_actions) AS configure, c.id AS credential_id, c.secret_data, c.secret_key_id, c.otp_last_step FROM user_sessions us JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id LEFT JOIN credentials c ON c.realm_id = u.realm_id AND c.user_id = u.id AND c.credential_type = 'otp' WHERE us.realm_id = $1 AND us.id = $2 AND us.revoked_at IS NULL AND us.expires_at > clock_timestamp()")
            .bind(realm_id).bind(session_id).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        let Some(row) = row else {
            return Ok(MfaStep::Complete);
        };
        if !row.try_get::<bool, _>("mfa_pending")? {
            return Ok(MfaStep::Complete);
        }
        Ok(match row.try_get::<Option<String>, _>("credential_id")? {
            Some(id) if !row.try_get::<bool, _>("configure")? => {
                MfaStep::VerifyTotp(OtpCredential {
                    id,
                    sealed: row.try_get("secret_data")?,
                    key_id: row.try_get("secret_key_id")?,
                    last_step: row.try_get("otp_last_step")?,
                })
            }
            _ => MfaStep::ConfigureTotp,
        })
    }

    /// Records an accepted code's step and completes the session, unless a
    /// concurrent request already used this or a later step.
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
            complete_session(conn, realm_id, session_id).await?;
        }
        tx.commit().await?;
        Ok(accepted)
    }

    /// Stores a newly set-up OTP credential, replacing any earlier one,
    /// clears the CONFIGURE_TOTP action and completes the session.
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
        let user: Option<String> = sqlx::query_scalar("SELECT user_id FROM user_sessions WHERE realm_id = $1 AND id = $2 AND mfa_pending AND revoked_at IS NULL AND expires_at > clock_timestamp() FOR UPDATE")
            .bind(realm_id).bind(session_id).fetch_optional(&mut *conn).await?;
        let Some(user) = user else {
            tx.commit().await?;
            return Ok(false);
        };
        sqlx::query("DELETE FROM credentials WHERE realm_id = $1 AND user_id = $2 AND credential_type = 'otp'")
            .bind(realm_id).bind(&user).execute(&mut *conn).await?;
        sqlx::query("INSERT INTO credentials (realm_id, id, user_id, credential_type, secret_data, secret_key_id, user_label, otp_last_step) VALUES ($1, $2, $3, 'otp', $4, $5, $6, $7)")
            .bind(realm_id).bind(credential_id).bind(&user).bind(sealed_seed).bind(key_id).bind(label).bind(step)
            .execute(&mut *conn).await?;
        sqlx::query("UPDATE users SET required_actions = array_remove(required_actions, 'CONFIGURE_TOTP') WHERE realm_id = $1 AND id = $2")
            .bind(realm_id).bind(&user).execute(&mut *conn).await?;
        complete_session(conn, realm_id, session_id).await?;
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
}
