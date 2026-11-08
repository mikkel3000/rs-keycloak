//! Admin realm localization texts.
//!
//! Follows `RealmLocalizationResource` at the pinned revision and
//! `tests/reference/realm-localization-observations.json`: reads need any
//! `realm-management` role, changes need `manage-realm`. A locale's texts
//! merge with the ones it has; a locale stays listed after its last text
//! is removed.

use std::collections::{BTreeMap, HashMap};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{FromRequest, Multipart, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Map, Value, json};

use super::users::json_response;
use super::{Access, AdminError, authorize};
use crate::oidc::OidcState;

pub(super) fn routes() -> Router<OidcState> {
    Router::new()
        .route("/admin/realms/{realm}/localization", get(locales))
        .route(
            "/admin/realms/{realm}/localization/{locale}",
            get(locale_texts).post(merge_texts).delete(delete_locale),
        )
        .route(
            "/admin/realms/{realm}/localization/{locale}/{key}",
            get(text).put(save_text).delete(delete_text),
        )
}

/// The request's media type, lowercased, without parameters.
fn media_type(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase())
        .unwrap_or_default()
}

/// The reference's answer to a body its method does not consume.
fn unsupported_media_type() -> AdminError {
    AdminError::Error(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "The content-type header value did not match the value in @Consumes".to_owned(),
    )
}

/// Reads a JSON object of texts; strings, numbers and booleans become
/// texts, as Jackson coerces scalars into a `Map<String, String>`.
pub(super) fn texts_of(fields: Map<String, Value>) -> Option<BTreeMap<String, String>> {
    fields
        .into_iter()
        .map(|(key, value)| match value {
            Value::String(text) => Some((key, text)),
            Value::Number(number) => Some((key, number.to_string())),
            Value::Bool(flag) => Some((key, flag.to_string())),
            _ => None,
        })
        .collect()
}

fn not_found(message: String) -> AdminError {
    AdminError::Error(StatusCode::NOT_FOUND, message)
}

/// The realm's ID and default locale.
async fn realm(state: &OidcState, name: &str) -> Result<(String, Option<String>), AdminError> {
    let realm = state
        .storage
        .realm_by_name(name)
        .await?
        .ok_or(AdminError::RealmNotFound)?;
    Ok((realm.id, realm.user_settings.default_locale))
}

async fn locales(
    State(state): State<OidcState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &name, Access::AnyRole).await?;
    let (realm_id, _) = realm(&state, &name).await?;
    let texts = state.storage.localization_texts(&realm_id).await?;
    Ok(json_response(json!(texts.keys().collect::<Vec<_>>())))
}

/// A locale's texts; with the deprecated `useRealmDefaultLocaleFallback`,
/// over the default locale's.
async fn locale_texts(
    State(state): State<OidcState>,
    Path((name, locale)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &name, Access::AnyRole).await?;
    let (realm_id, default_locale) = realm(&state, &name).await?;
    let mut all = state.storage.localization_texts(&realm_id).await?;
    let mut texts = BTreeMap::new();
    if params
        .get("useRealmDefaultLocaleFallback")
        .map(String::as_str)
        == Some("true")
        && let Some(default) = default_locale.filter(|tag| !tag.trim().is_empty())
    {
        texts.extend(all.get(&default).cloned().unwrap_or_default());
    }
    texts.extend(all.remove(&locale).unwrap_or_default());
    Ok(json_response(json!(texts)))
}

async fn text(
    State(state): State<OidcState>,
    Path((name, locale, key)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &name, Access::AnyRole).await?;
    let (realm_id, _) = realm(&state, &name).await?;
    match state
        .storage
        .localization_text(&realm_id, &locale, &key)
        .await?
    {
        Some(text) => {
            Ok(([(header::CONTENT_TYPE, "text/plain;charset=UTF-8")], text).into_response())
        }
        None => Err(not_found("Localization text not found".to_owned())),
    }
}

/// Sets one text from a `text/plain` body.
async fn save_text(
    State(state): State<OidcState>,
    Path((name, locale, key)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    if media_type(&headers) != "text/plain" {
        return Err(unsupported_media_type());
    }
    let actor = authorize(&state, &headers, &name, Access::ManageRealm).await?;
    let (realm_id, _) = realm(&state, &name).await?;
    let text = String::from_utf8(body.to_vec())
        .map_err(|_| AdminError::bad_request("unable to read contents from stream"))?;
    let texts = BTreeMap::from([(key, text)]);
    state
        .storage
        .save_localization_texts(&realm_id, &locale, &texts, &actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Merges texts from a JSON body, or from the `file` part of a form upload.
async fn merge_texts(
    State(state): State<OidcState>,
    Path((name, locale)): Path<(String, String)>,
    headers: HeaderMap,
    request: Request,
) -> Result<StatusCode, AdminError> {
    let media = media_type(&headers);
    let upload = match media.as_str() {
        "application/json" => false,
        "multipart/form-data" => true,
        _ => return Err(unsupported_media_type()),
    };
    let actor = authorize(&state, &headers, &name, Access::ManageRealm).await?;
    let (realm_id, _) = realm(&state, &name).await?;
    let texts = if upload {
        uploaded_texts(
            Multipart::from_request(request, &state)
                .await
                .map_err(|_| no_file())?,
        )
        .await?
    } else {
        let body = Bytes::from_request(request, &state)
            .await
            .map_err(|_| AdminError::bad_request("unable to read contents from stream"))?;
        let unparsable = || {
            AdminError::OAuth(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Cannot parse the JSON",
            )
        };
        match serde_json::from_slice(&body) {
            Ok(Value::Object(fields)) => texts_of(fields).ok_or_else(unparsable)?,
            _ => return Err(unparsable()),
        }
    };
    state
        .storage
        .save_localization_texts(&realm_id, &locale, &texts, &actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn no_file() -> AdminError {
    AdminError::Error(StatusCode::BAD_REQUEST, "HTTP 400 Bad Request".to_owned())
}

/// The texts of an upload's `file` part, a JSON object.
async fn uploaded_texts(mut form: Multipart) -> Result<BTreeMap<String, String>, AdminError> {
    let unreadable =
        || AdminError::Error(StatusCode::BAD_REQUEST, "Could not read file.".to_owned());
    while let Some(field) = form.next_field().await.map_err(|_| no_file())? {
        if field.name() != Some("file") {
            continue;
        }
        let data = field.bytes().await.map_err(|_| unreadable())?;
        return match serde_json::from_slice(&data) {
            Ok(Value::Object(fields)) => texts_of(fields).ok_or_else(unreadable),
            _ => Err(unreadable()),
        };
    }
    Err(no_file())
}

async fn delete_locale(
    State(state): State<OidcState>,
    Path((name, locale)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers, &name, Access::ManageRealm).await?;
    let (realm_id, _) = realm(&state, &name).await?;
    if state
        .storage
        .delete_localization_locale(&realm_id, &locale, &actor)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(not_found(format!(
            "No localization texts for locale {locale} found."
        )))
    }
}

async fn delete_text(
    State(state): State<OidcState>,
    Path((name, locale, key)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    let actor = authorize(&state, &headers, &name, Access::ManageRealm).await?;
    let (realm_id, _) = realm(&state, &name).await?;
    if state
        .storage
        .delete_localization_text(&realm_id, &locale, &key, &actor)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(not_found("Localization text not found".to_owned()))
    }
}
