//! Realm localization texts, as the reference's `RealmLocalizationResource`
//! and JPA realm provider keep them: per locale, a map of keys to texts.
//!
//! A locale exists once texts were saved for it, even an empty map, and
//! stays listed after its last text is removed.

use std::collections::BTreeMap;

use sqlx::Row;

use crate::{Actor, Storage, StorageError, audit};

/// Every locale of a realm with its texts.
pub type LocalizationTexts = BTreeMap<String, BTreeMap<String, String>>;

/// Longest locale accepted.
const MAX_LOCALE: usize = 255;

/// Reads every locale of a realm with its texts.
pub(crate) async fn realm_texts(
    connection: &mut sqlx::PgConnection,
    realm_id: &str,
) -> Result<LocalizationTexts, StorageError> {
    let rows = sqlx::query("SELECT l.locale, t.key, t.value FROM realm_localizations l LEFT JOIN LATERAL jsonb_each_text(l.texts) t ON true WHERE l.realm_id = $1")
        .bind(realm_id)
        .fetch_all(connection)
        .await?;
    let mut texts = LocalizationTexts::new();
    for row in rows {
        let locale: String = row.try_get("locale")?;
        let entry = texts.entry(locale).or_default();
        if let Some(key) = row.try_get::<Option<String>, _>("key")? {
            entry.insert(
                key,
                row.try_get::<Option<String>, _>("value")?
                    .unwrap_or_default(),
            );
        }
    }
    Ok(texts)
}

/// Adds or replaces texts of a locale, creating the locale if needed.
pub(crate) async fn merge_texts(
    connection: &mut sqlx::PgConnection,
    realm_id: &str,
    locale: &str,
    texts: &BTreeMap<String, String>,
) -> Result<(), StorageError> {
    if locale.is_empty() || locale.len() > MAX_LOCALE {
        return Err(StorageError::InvalidInput);
    }
    let keys: Vec<&str> = texts.keys().map(String::as_str).collect();
    let values: Vec<&str> = texts.values().map(String::as_str).collect();
    sqlx::query("INSERT INTO realm_localizations (realm_id, locale, texts) VALUES ($1, $2, jsonb_object($3::text[], $4::text[])) ON CONFLICT (realm_id, locale) DO UPDATE SET texts = realm_localizations.texts || EXCLUDED.texts")
        .bind(realm_id)
        .bind(locale)
        .bind(&keys)
        .bind(&values)
        .execute(connection)
        .await?;
    Ok(())
}

impl Storage {
    /// Reads every locale of a realm with its texts.
    pub async fn localization_texts(
        &self,
        realm_id: &str,
    ) -> Result<LocalizationTexts, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let texts = realm_texts(tx.connection(), realm_id).await?;
        tx.commit().await?;
        Ok(texts)
    }

    /// Reads one text of a locale, if set.
    pub async fn localization_text(
        &self,
        realm_id: &str,
        locale: &str,
        key: &str,
    ) -> Result<Option<String>, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let text = sqlx::query_scalar(
            "SELECT texts ->> $3 FROM realm_localizations WHERE realm_id = $1 AND locale = $2",
        )
        .bind(realm_id)
        .bind(locale)
        .bind(key)
        .fetch_optional(tx.connection())
        .await?
        .flatten();
        tx.commit().await?;
        Ok(text)
    }

    /// Adds or replaces texts of a locale, creating the locale if needed.
    pub async fn save_localization_texts(
        &self,
        realm_id: &str,
        locale: &str,
        texts: &BTreeMap<String, String>,
        actor: &Actor,
    ) -> Result<(), StorageError> {
        let mut tx = self.begin_request(false).await?;
        let connection = tx.connection();
        merge_texts(&mut *connection, realm_id, locale, texts).await?;
        audit(connection, actor, "realm_localization_updated").await?;
        tx.commit().await?;
        Ok(())
    }

    /// Removes a locale and its texts; returns false if it had none.
    pub async fn delete_localization_locale(
        &self,
        realm_id: &str,
        locale: &str,
        actor: &Actor,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let connection = tx.connection();
        let removed =
            sqlx::query("DELETE FROM realm_localizations WHERE realm_id = $1 AND locale = $2")
                .bind(realm_id)
                .bind(locale)
                .execute(&mut *connection)
                .await?
                .rows_affected();
        if removed == 1 {
            audit(connection, actor, "realm_localization_deleted").await?;
        }
        tx.commit().await?;
        Ok(removed == 1)
    }

    /// Removes one text of a locale, keeping the locale; returns false if
    /// the text was not set.
    pub async fn delete_localization_text(
        &self,
        realm_id: &str,
        locale: &str,
        key: &str,
        actor: &Actor,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let connection = tx.connection();
        let removed = sqlx::query("UPDATE realm_localizations SET texts = texts - $3 WHERE realm_id = $1 AND locale = $2 AND texts ? $3")
            .bind(realm_id)
            .bind(locale)
            .bind(key)
            .execute(&mut *connection)
            .await?
            .rows_affected();
        if removed == 1 {
            audit(connection, actor, "realm_localization_updated").await?;
        }
        tx.commit().await?;
        Ok(removed == 1)
    }
}
