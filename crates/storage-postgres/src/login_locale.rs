//! The locale state of an authorization request: the client's `ui_locales`,
//! the locale the user picked with `kc_locale`, and the user's own locale,
//! as the reference keeps them in the authentication session and user.

use sqlx::Row;

use crate::localization::{LocalizationTexts, realm_texts};
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
    /// The realm's display name, else its name, as login pages name it.
    pub realm_label: String,
    /// The realm's localization texts, which override the theme's
    /// messages.
    pub texts: LocalizationTexts,
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
        let row = sqlx::query("SELECT r.internationalization_enabled, r.supported_locales, r.default_locale, r.edit_username_allowed, r.registration_email_as_username, r.login_with_email_allowed, r.duplicate_emails_allowed, COALESCE(NULLIF(r.display_name, ''), r.name) AS realm_label, a.requested_locale, a.ui_locales, u.locale FROM authorization_requests a JOIN realms r ON r.id = a.realm_id LEFT JOIN user_sessions us ON us.realm_id = a.realm_id AND us.id = a.pending_session_id LEFT JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id WHERE a.realm_id = $1 AND a.id = $2 AND a.consumed_at IS NULL AND a.expires_at > clock_timestamp()")
            .bind(realm_id)
            .bind(request_id)
            .fetch_optional(tx.connection())
            .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let texts = realm_texts(tx.connection(), realm_id).await?;
        tx.commit().await?;
        Ok(Some(LoginLocale {
            settings: user_settings_row(&row)?,
            requested: row.try_get("requested_locale")?,
            user: row.try_get("locale")?,
            client: row.try_get("ui_locales")?,
            realm_label: row.try_get("realm_label")?,
            texts,
        }))
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

    /// Reads the locale state of a realm for a page outside any live
    /// request: the realm's settings and label alone.
    pub async fn realm_locale(&self, realm_id: &str) -> Result<LoginLocale, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query("SELECT internationalization_enabled, supported_locales, default_locale, edit_username_allowed, registration_email_as_username, login_with_email_allowed, duplicate_emails_allowed, COALESCE(NULLIF(display_name, ''), name) AS realm_label FROM realms WHERE id = $1")
            .bind(realm_id)
            .fetch_one(tx.connection())
            .await?;
        let texts = realm_texts(tx.connection(), realm_id).await?;
        tx.commit().await?;
        Ok(LoginLocale {
            settings: user_settings_row(&row)?,
            realm_label: row.try_get("realm_label")?,
            texts,
            ..LoginLocale::default()
        })
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
        self.apply_requested_locale_where(
            realm_id,
            request_id,
            "FROM user_sessions us JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id WHERE us.realm_id = $1 AND us.id = $3",
            session_id,
        )
        .await
    }

    /// Stores the locale the request picked as a user's own, as
    /// `apply_requested_locale` does, for a user known before a session
    /// exists, such as the one an emailed link names.
    pub async fn apply_requested_locale_to_user(
        &self,
        realm_id: &str,
        request_id: &str,
        user_id: &str,
    ) -> Result<Option<UserLocaleUpdate>, StorageError> {
        self.apply_requested_locale_where(
            realm_id,
            request_id,
            "FROM users u WHERE u.realm_id = $1 AND u.id = $3",
            user_id,
        )
        .await
    }

    /// Applies the request's pick to the user that `user_rows` (with `$3`
    /// bound to `user_key`) selects.
    async fn apply_requested_locale_where(
        &self,
        realm_id: &str,
        request_id: &str,
        user_rows: &str,
        user_key: &str,
    ) -> Result<Option<UserLocaleUpdate>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let conn = tx.connection();
        let row = sqlx::query(&format!("SELECT u.id, u.locale, (SELECT a.requested_locale FROM authorization_requests a WHERE a.realm_id = $1 AND a.id = $2) AS requested {user_rows} FOR UPDATE OF u"))
            .bind(realm_id)
            .bind(request_id)
            .bind(user_key)
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
