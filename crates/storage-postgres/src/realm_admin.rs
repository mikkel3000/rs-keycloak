//! Realm administration and master-realm administrator checks.

use sqlx::Row;
use sqlx::postgres::PgRow;

use crate::event_settings::{
    EVENT_SETTING_COLUMNS, EventSettingChanges, EventSettings, change_event_settings,
    event_settings_row,
};
use crate::localization::{LocalizationTexts, merge_texts};
use crate::login_settings::{
    BRUTE_FORCE_COLUMNS, LOGIN_SETTING_COLUMNS, LoginSettingChanges, LoginSettings,
    change_login_settings, login_settings_row,
};
use crate::{Actor, Storage, StorageError, audit};

/// The administrative realm; it cannot be deleted.
pub const MASTER_REALM: &str = "master";

/// A realm as stored, including disabled realms.
pub struct RealmRecord {
    /// Stable realm identifier.
    pub id: String,
    /// Realm name used in URLs.
    pub name: String,
    /// Whether the realm serves authentication.
    pub enabled: bool,
    /// SMTP settings, if the realm has a mail server.
    pub smtp: Option<RealmSmtp>,
    /// Whether the login page offers forgot-password.
    pub reset_password_allowed: bool,
    /// Whether users must verify their email at login.
    pub verify_email: bool,
    /// Name shown to users, if set.
    pub display_name: Option<String>,
    /// Lifetime of issued access and ID tokens in seconds.
    pub access_token_lifespan: i32,
    /// Locale and username settings.
    pub user_settings: UserSettings,
    /// Login-flow settings.
    pub login: LoginSettings,
    /// Login and admin event settings.
    pub events: EventSettings,
}

/// The settings that decide a realm's page locale and username rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSettings {
    /// Whether pages follow the visitor's locale.
    pub internationalization_enabled: bool,
    /// Locales users may choose, sorted; kept while internationalization is
    /// off.
    pub supported_locales: Vec<String>,
    /// Locale used when no supported locale matches, if set; may be empty.
    pub default_locale: Option<String>,
    /// Whether users may change their own username.
    pub edit_username_allowed: bool,
    /// Whether the username always equals the email.
    pub registration_email_as_username: bool,
    /// Whether users may sign in with their email.
    pub login_with_email_allowed: bool,
    /// Whether several users may share an email; excludes email login and
    /// email as username.
    pub duplicate_emails_allowed: bool,
}

impl Default for UserSettings {
    /// A new realm's settings: email login on, everything else off.
    fn default() -> Self {
        Self {
            internationalization_enabled: false,
            supported_locales: Vec::new(),
            default_locale: None,
            edit_username_allowed: false,
            registration_email_as_username: false,
            login_with_email_allowed: true,
            duplicate_emails_allowed: false,
        }
    }
}

impl UserSettings {
    /// Applies the email settings a request gives, in the reference's
    /// order: email as username, then email login, which turns duplicates
    /// off, then duplicates, which turn the other two off.
    pub fn apply_email_rules(&mut self, changes: &UserSettingChanges<'_>) {
        let (email_as_username, email_login, duplicates) = changes.email_rules();
        if let Some(value) = email_as_username {
            self.registration_email_as_username = value;
        }
        if let Some(value) = email_login {
            self.login_with_email_allowed = value;
        }
        if let Some(value) = duplicates {
            self.duplicate_emails_allowed = value;
        }
    }
}

impl UserSettingChanges<'_> {
    /// The email-as-username, email-login and duplicate-email changes once
    /// each setting given has turned off the ones it excludes, in the
    /// reference's order.
    fn email_rules(&self) -> (Option<bool>, Option<bool>, Option<bool>) {
        let mut email_as_username = self.registration_email_as_username;
        let mut email_login = self.login_with_email_allowed;
        let mut duplicates = self.duplicate_emails_allowed;
        if email_login == Some(true) && duplicates.is_none() {
            duplicates = Some(false);
        }
        if duplicates == Some(true) {
            email_login = Some(false);
            email_as_username = Some(false);
        }
        (email_as_username, email_login, duplicates)
    }
}

/// Settings for a new realm.
pub struct RealmSettings {
    /// Whether the realm serves authentication.
    pub enabled: bool,
    /// Whether the login page offers forgot-password.
    pub reset_password_allowed: bool,
    /// Whether users must verify their email at login.
    pub verify_email: bool,
    /// SMTP settings, if any.
    pub smtp: Option<RealmSmtp>,
    /// Name shown to users, if set.
    pub display_name: Option<String>,
    /// Lifetime of issued access and ID tokens in seconds.
    pub access_token_lifespan: i32,
    /// Locale and username settings.
    pub user_settings: UserSettings,
    /// Localization texts given at creation.
    pub localization_texts: LocalizationTexts,
    /// Login-flow settings given at creation, over the defaults.
    pub login: LoginSettingChanges,
    /// Event settings given at creation, over the defaults.
    pub events: EventSettingChanges,
}

/// Changes to a realm's locale and username settings; `None` keeps one.
#[derive(Default)]
pub struct UserSettingChanges<'a> {
    /// Whether pages follow the visitor's locale.
    pub internationalization_enabled: Option<bool>,
    /// Locales users may choose, sorted.
    pub supported_locales: Option<&'a [String]>,
    /// Locale used when no supported locale matches.
    pub default_locale: Option<&'a str>,
    /// Whether users may change their own username.
    pub edit_username_allowed: Option<bool>,
    /// Whether the username always equals the email.
    pub registration_email_as_username: Option<bool>,
    /// Whether users may sign in with their email.
    pub login_with_email_allowed: Option<bool>,
    /// Whether several users may share an email.
    pub duplicate_emails_allowed: Option<bool>,
}

/// Changes to a realm; `None` keeps a setting, and for SMTP and the display
/// name `Some(None)` removes it.
#[derive(Default)]
pub struct RealmChanges<'a> {
    /// Whether the realm serves authentication.
    pub enabled: Option<bool>,
    /// Whether the login page offers forgot-password.
    pub reset_password_allowed: Option<bool>,
    /// Whether users must verify their email at login.
    pub verify_email: Option<bool>,
    /// SMTP settings.
    pub smtp: Option<Option<&'a RealmSmtp>>,
    /// Name shown to users.
    pub display_name: Option<Option<&'a str>>,
    /// Lifetime of issued access and ID tokens in seconds.
    pub access_token_lifespan: Option<i32>,
    /// Locale and username settings.
    pub user_settings: UserSettingChanges<'a>,
    /// Login-flow settings.
    pub login: LoginSettingChanges,
    /// Event settings.
    pub events: EventSettingChanges,
}

/// A realm's SMTP settings as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmSmtp {
    /// Server host.
    pub host: String,
    /// Server port.
    pub port: i32,
    /// Sender address, if set.
    pub from: Option<String>,
    /// Sender display name, if set.
    pub from_display_name: Option<String>,
    /// Upgrade with STARTTLS.
    pub starttls: bool,
    /// Connect with implicit TLS.
    pub ssl: bool,
}

/// Outcome of creating a realm.
pub enum RealmCreation {
    /// The realm was created.
    Created,
    /// A realm with this name already exists.
    Exists,
    /// Another realm already has the given id.
    IdTaken,
}

/// Outcome of deleting a realm.
pub enum RealmDeletion {
    /// The realm and all of its data were removed.
    Deleted,
    /// No realm with this name exists.
    NotFound,
    /// The master realm cannot be removed.
    Master,
}

const REALM_COLUMNS: &str = "id, name, enabled, reset_password_allowed, verify_email, smtp_host, smtp_port, smtp_from, smtp_from_display_name, smtp_starttls, smtp_ssl, display_name, access_token_lifespan, internationalization_enabled, supported_locales, default_locale, edit_username_allowed, registration_email_as_username, login_with_email_allowed, duplicate_emails_allowed";

pub(crate) fn user_settings_row(row: &PgRow) -> Result<UserSettings, StorageError> {
    Ok(UserSettings {
        internationalization_enabled: row.try_get("internationalization_enabled")?,
        supported_locales: row.try_get("supported_locales")?,
        default_locale: row.try_get("default_locale")?,
        edit_username_allowed: row.try_get("edit_username_allowed")?,
        registration_email_as_username: row.try_get("registration_email_as_username")?,
        login_with_email_allowed: row.try_get("login_with_email_allowed")?,
        duplicate_emails_allowed: row.try_get("duplicate_emails_allowed")?,
    })
}

fn realm_row(row: &PgRow) -> Result<RealmRecord, StorageError> {
    let host: Option<String> = row.try_get("smtp_host")?;
    let port: Option<i32> = row.try_get("smtp_port")?;
    Ok(RealmRecord {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        enabled: row.try_get("enabled")?,
        reset_password_allowed: row.try_get("reset_password_allowed")?,
        verify_email: row.try_get("verify_email")?,
        display_name: row.try_get("display_name")?,
        access_token_lifespan: row.try_get("access_token_lifespan")?,
        user_settings: user_settings_row(row)?,
        login: login_settings_row(row)?,
        events: event_settings_row(row)?,
        smtp: match host.zip(port) {
            Some((host, port)) => Some(RealmSmtp {
                host,
                port,
                from: row.try_get("smtp_from")?,
                from_display_name: row.try_get("smtp_from_display_name")?,
                starttls: row.try_get("smtp_starttls")?,
                ssl: row.try_get("smtp_ssl")?,
            }),
            None => None,
        },
    })
}

impl Storage {
    /// Reports whether a master-realm user holds the master `admin` role.
    pub async fn is_master_admin(&self, user_id: &str) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let admin = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_role_grants g JOIN roles r ON r.realm_id = g.realm_id AND r.id = g.role_id JOIN users u ON u.realm_id = g.realm_id AND u.id = g.user_id WHERE g.realm_id = $1 AND g.user_id = $2 AND r.name = 'admin' AND u.enabled)")
            .bind(MASTER_REALM).bind(user_id).fetch_one(tx.connection()).await?;
        tx.commit().await?;
        Ok(admin)
    }

    /// Grants the master `admin` role to a master client's service account.
    ///
    /// Returns false if the client or its service account does not exist.
    pub async fn grant_master_admin(&self, client_identifier: &str) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let granted = sqlx::query("INSERT INTO user_role_grants (realm_id, user_id, role_id) SELECT u.realm_id, u.id, r.id FROM users u JOIN clients c ON c.realm_id = u.realm_id AND c.id = u.service_account_client_id JOIN roles r ON r.realm_id = u.realm_id AND r.name = 'admin' WHERE u.realm_id = $1 AND c.client_id = $2 AND c.service_accounts_enabled ON CONFLICT DO NOTHING RETURNING user_id")
            .bind(MASTER_REALM).bind(client_identifier).fetch_optional(tx.connection()).await?;
        let exists = match granted {
            Some(_) => true,
            None => sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users u JOIN clients c ON c.realm_id = u.realm_id AND c.id = u.service_account_client_id WHERE u.realm_id = $1 AND c.client_id = $2 AND c.service_accounts_enabled)")
                .bind(MASTER_REALM).bind(client_identifier).fetch_one(tx.connection()).await?,
        };
        tx.commit().await?;
        Ok(exists)
    }

    /// Looks up a realm by name whether or not it is enabled.
    pub async fn realm_by_name(&self, name: &str) -> Result<Option<RealmRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let row = sqlx::query(&format!(
            "SELECT {REALM_COLUMNS}, {LOGIN_SETTING_COLUMNS}, {BRUTE_FORCE_COLUMNS}, {EVENT_SETTING_COLUMNS} FROM realms WHERE name = $1"
        ))
        .bind(name)
        .fetch_optional(tx.connection())
        .await?;
        tx.commit().await?;
        row.as_ref().map(realm_row).transpose()
    }

    /// Reads the lifetime in seconds of the access and ID tokens a realm
    /// issues.
    pub async fn access_token_lifespan(&self, realm_id: &str) -> Result<i32, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let lifespan = sqlx::query_scalar("SELECT access_token_lifespan FROM realms WHERE id = $1")
            .bind(realm_id)
            .fetch_one(tx.connection())
            .await?;
        tx.commit().await?;
        Ok(lifespan)
    }

    /// Reads a realm's locale and username settings.
    pub async fn user_settings(&self, realm_id: &str) -> Result<UserSettings, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let row = sqlx::query("SELECT internationalization_enabled, supported_locales, default_locale, edit_username_allowed, registration_email_as_username, login_with_email_allowed, duplicate_emails_allowed FROM realms WHERE id = $1")
            .bind(realm_id)
            .fetch_one(tx.connection())
            .await?;
        tx.commit().await?;
        user_settings_row(&row)
    }

    /// Lists every realm by name.
    pub async fn realms(&self) -> Result<Vec<RealmRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query(&format!(
            "SELECT {REALM_COLUMNS}, {LOGIN_SETTING_COLUMNS}, {BRUTE_FORCE_COLUMNS}, {EVENT_SETTING_COLUMNS} FROM realms ORDER BY name"
        ))
        .fetch_all(tx.connection())
        .await?;
        tx.commit().await?;
        rows.iter().map(realm_row).collect()
    }

    /// Creates a realm and records the action in the master audit log.
    pub async fn create_realm(
        &self,
        realm_id: &str,
        name: &str,
        settings: &RealmSettings,
        actor: &Actor,
    ) -> Result<RealmCreation, StorageError> {
        let smtp = settings.smtp.as_ref();
        let mut tx = self.begin_request(false).await?;
        let users = &settings.user_settings;
        let created: Option<String> = sqlx::query_scalar("INSERT INTO realms (id, name, enabled, smtp_host, smtp_port, smtp_from, smtp_from_display_name, smtp_starttls, smtp_ssl, reset_password_allowed, verify_email, display_name, access_token_lifespan, internationalization_enabled, supported_locales, default_locale, edit_username_allowed, registration_email_as_username, login_with_email_allowed, duplicate_emails_allowed) VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, false), COALESCE($9, false), $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20) ON CONFLICT DO NOTHING RETURNING id")
            .bind(realm_id).bind(name).bind(settings.enabled)
            .bind(smtp.map(|smtp| smtp.host.as_str())).bind(smtp.map(|smtp| smtp.port))
            .bind(smtp.and_then(|smtp| smtp.from.as_deref())).bind(smtp.and_then(|smtp| smtp.from_display_name.as_deref()))
            .bind(smtp.map(|smtp| smtp.starttls)).bind(smtp.map(|smtp| smtp.ssl)).bind(settings.reset_password_allowed).bind(settings.verify_email)
            .bind(settings.display_name.as_deref()).bind(settings.access_token_lifespan)
            .bind(users.internationalization_enabled).bind(&users.supported_locales).bind(users.default_locale.as_deref())
            .bind(users.edit_username_allowed).bind(users.registration_email_as_username)
            .bind(users.login_with_email_allowed).bind(users.duplicate_emails_allowed)
            .fetch_optional(tx.connection()).await?;
        if created.is_none() {
            let name_taken: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM realms WHERE name = $1)")
                    .bind(name)
                    .fetch_one(tx.connection())
                    .await?;
            tx.commit().await?;
            return Ok(if name_taken {
                RealmCreation::Exists
            } else {
                RealmCreation::IdTaken
            });
        }
        change_login_settings(tx.connection(), name, &settings.login).await?;
        change_event_settings(tx.connection(), name, &settings.events).await?;
        for (locale, texts) in &settings.localization_texts {
            merge_texts(tx.connection(), realm_id, locale, texts).await?;
        }
        audit(tx.connection(), actor, "realm_created").await?;
        tx.commit().await?;
        Ok(RealmCreation::Created)
    }

    /// Applies changes to a realm; returns false if the realm is missing.
    pub async fn update_realm(
        &self,
        name: &str,
        changes: &RealmChanges<'_>,
        actor: &Actor,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let replace_smtp = changes.smtp.is_some();
        let smtp = changes.smtp.flatten();
        let users = &changes.user_settings;
        let (email_as_username, email_login, duplicates) = users.email_rules();
        let changed = sqlx::query("UPDATE realms SET enabled = COALESCE($2, enabled), reset_password_allowed = COALESCE($10, reset_password_allowed), verify_email = COALESCE($11, verify_email), smtp_host = CASE WHEN $3 THEN $4 ELSE smtp_host END, smtp_port = CASE WHEN $3 THEN $5 ELSE smtp_port END, smtp_from = CASE WHEN $3 THEN $6 ELSE smtp_from END, smtp_from_display_name = CASE WHEN $3 THEN $7 ELSE smtp_from_display_name END, smtp_starttls = CASE WHEN $3 THEN COALESCE($8, false) ELSE smtp_starttls END, smtp_ssl = CASE WHEN $3 THEN COALESCE($9, false) ELSE smtp_ssl END, display_name = CASE WHEN $12 THEN $13 ELSE display_name END, access_token_lifespan = COALESCE($14, access_token_lifespan), internationalization_enabled = COALESCE($15, internationalization_enabled), supported_locales = COALESCE($16, supported_locales), default_locale = COALESCE($17, default_locale), edit_username_allowed = COALESCE($18, edit_username_allowed), registration_email_as_username = COALESCE($19, registration_email_as_username), login_with_email_allowed = COALESCE($20, login_with_email_allowed), duplicate_emails_allowed = COALESCE($21, duplicate_emails_allowed) WHERE name = $1")
            .bind(name).bind(changes.enabled).bind(replace_smtp)
            .bind(smtp.map(|smtp| smtp.host.as_str())).bind(smtp.map(|smtp| smtp.port))
            .bind(smtp.and_then(|smtp| smtp.from.as_deref())).bind(smtp.and_then(|smtp| smtp.from_display_name.as_deref()))
            .bind(smtp.map(|smtp| smtp.starttls)).bind(smtp.map(|smtp| smtp.ssl)).bind(changes.reset_password_allowed).bind(changes.verify_email)
            .bind(changes.display_name.is_some()).bind(changes.display_name.flatten()).bind(changes.access_token_lifespan)
            .bind(users.internationalization_enabled).bind(users.supported_locales).bind(users.default_locale)
            .bind(users.edit_username_allowed).bind(email_as_username)
            .bind(email_login).bind(duplicates)
            .execute(&mut *conn).await?.rows_affected();
        if changed == 0 {
            tx.commit().await?;
            return Ok(false);
        }
        change_login_settings(&mut *conn, name, &changes.login).await?;
        change_event_settings(&mut *conn, name, &changes.events).await?;
        audit(&mut *conn, actor, "realm_updated").await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Deletes a realm and its data, recording the action in the master audit log.
    pub async fn delete_realm(
        &self,
        name: &str,
        actor: &Actor,
    ) -> Result<RealmDeletion, StorageError> {
        if name == MASTER_REALM {
            return Ok(RealmDeletion::Master);
        }
        let mut tx = self.begin_request(false).await?;
        let deleted = sqlx::query("DELETE FROM realms WHERE name = $1 AND id <> $2")
            .bind(name)
            .bind(MASTER_REALM)
            .execute(tx.connection())
            .await?
            .rows_affected();
        if deleted == 0 {
            tx.commit().await?;
            return Ok(RealmDeletion::NotFound);
        }
        audit(tx.connection(), actor, "realm_deleted").await?;
        tx.commit().await?;
        Ok(RealmDeletion::Deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn applied(changes: UserSettingChanges<'_>) -> (bool, bool, bool) {
        let mut settings = UserSettings::default();
        settings.apply_email_rules(&changes);
        (
            settings.registration_email_as_username,
            settings.login_with_email_allowed,
            settings.duplicate_emails_allowed,
        )
    }

    #[test]
    fn each_email_setting_turns_off_the_ones_it_excludes() {
        let all = UserSettingChanges {
            registration_email_as_username: Some(true),
            login_with_email_allowed: Some(true),
            duplicate_emails_allowed: Some(true),
            ..UserSettingChanges::default()
        };
        assert_eq!(applied(all), (false, false, true));
        let email_login = UserSettingChanges {
            login_with_email_allowed: Some(true),
            ..UserSettingChanges::default()
        };
        assert_eq!(email_login.email_rules(), (None, Some(true), Some(false)));
        let email_as_username = UserSettingChanges {
            registration_email_as_username: Some(true),
            ..UserSettingChanges::default()
        };
        assert_eq!(email_as_username.email_rules(), (Some(true), None, None));
    }
}
