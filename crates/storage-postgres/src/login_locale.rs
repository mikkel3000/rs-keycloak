//! The locale state of an authorization request: the client's `ui_locales`,
//! the locale the user picked with `kc_locale`, and the user's own locale,
//! as the reference keeps them in the authentication session and user.

use sqlx::Row;

use crate::realm_admin::user_settings_row;
use crate::{Storage, StorageError, UserSettings};

/// What decides the locale of a request's pages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoginLocale {
    /// The realm's locale settings.
    pub settings: UserSettings,
    /// The locale the user picked with `kc_locale`, as sent.
    pub requested: Option<String>,
    /// The user's stored locale, once the request has authenticated a user.
    pub user: Option<String>,
    /// The client's space-separated `ui_locales`, as sent.
    pub client: Option<String>,
}

/// A user's locale before and after a login applied the request's choice.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserLocaleUpdate {
    /// The locale the request picked, if any.
    pub requested: Option<String>,
    /// The user's locale before the update.
    pub previous: Option<String>,
}

impl Storage {
    /// Reads the locale state of a live authorization request of the realm;
    /// `None` when there is no such request.
    pub async fn login_locale(
        &self,
        realm_id: &str,
        request_id: &str,
    ) -> Result<Option<LoginLocale>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query("SELECT r.internationalization_enabled, r.supported_locales, r.default_locale, r.edit_username_allowed, r.registration_email_as_username, a.requested_locale, a.ui_locales, u.locale FROM authorization_requests a JOIN realms r ON r.id = a.realm_id LEFT JOIN user_sessions us ON us.realm_id = a.realm_id AND us.id = a.pending_session_id LEFT JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id WHERE a.realm_id = $1 AND a.id = $2 AND a.consumed_at IS NULL AND a.expires_at > clock_timestamp()")
            .bind(realm_id)
            .bind(request_id)
            .fetch_optional(tx.connection())
            .await?;
        tx.commit().await?;
        row.map(|row| {
            Ok(LoginLocale {
                settings: user_settings_row(&row)?,
                requested: row.try_get("requested_locale")?,
                user: row.try_get("locale")?,
                client: row.try_get("ui_locales")?,
            })
        })
        .transpose()
    }

    /// Keeps the locale a user picked with `kc_locale` for the rest of a
    /// live request; returns whether the request exists.
    pub async fn request_locale(
        &self,
        realm_id: &str,
        request_id: &str,
        locale: &str,
    ) -> Result<bool, StorageError> {
        if locale.is_empty() || locale.len() > 255 {
            return Err(StorageError::InvalidInput);
        }
        let mut tx = self.begin_request(true).await?;
        let changed = sqlx::query("UPDATE authorization_requests SET requested_locale = $3 WHERE realm_id = $1 AND id = $2 AND consumed_at IS NULL AND expires_at > clock_timestamp()")
            .bind(realm_id)
            .bind(request_id)
            .bind(locale)
            .execute(tx.connection())
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(changed == 1)
    }

    /// Stores the locale the request picked as the session user's own, as
    /// the reference's locale required action does when it differs; returns
    /// both values, or `None` when the session has no user.
    pub async fn apply_requested_locale(
        &self,
        realm_id: &str,
        request_id: &str,
        session_id: &str,
    ) -> Result<Option<UserLocaleUpdate>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let row = sqlx::query("SELECT u.id, u.locale, (SELECT a.requested_locale FROM authorization_requests a WHERE a.realm_id = $1 AND a.id = $2) AS requested FROM user_sessions us JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id WHERE us.realm_id = $1 AND us.id = $3 FOR UPDATE OF u")
            .bind(realm_id)
            .bind(request_id)
            .bind(session_id)
            .fetch_optional(&mut *conn)
            .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let update = UserLocaleUpdate {
            requested: row.try_get("requested")?,
            previous: row.try_get("locale")?,
        };
        if let Some(requested) = &update.requested
            && update.previous.as_ref() != Some(requested)
        {
            sqlx::query("UPDATE users SET locale = $3 WHERE realm_id = $1 AND id = $2")
                .bind(realm_id)
                .bind(row.try_get::<String, _>("id")?)
                .bind(requested)
                .execute(&mut *conn)
                .await?;
        }
        tx.commit().await?;
        Ok(Some(update))
    }
}
