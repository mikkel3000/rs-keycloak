//! OIDC logout: refresh-token POST logout and RP-initiated browser logout.
//!
//! Follows the recorded cases in `tests/reference/logout-observations.json`.
//! There is no SSO cookie yet, so browser logout ends only the session named
//! by `id_token_hint`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use rs_keycloak_crypto::signing::VerifiedIdToken;
use rs_keycloak_protocols::client_urls::{redirect_matches, resolve_redirect};
use rs_keycloak_storage_postgres::RefreshLogout;
use serde_json::json;
use url::Url;
use zeroize::Zeroizing;

use crate::client_auth::{self, ClientAuthResult, InvalidClientAuthentication};

use super::{
    OidcState, digest, invalid_client, sso_cookies, unavailable, valid_realm, verified_refresh,
};

fn page(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-cache")],
        Html(format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Logout</title></head><body><p>{message}</p></body></html>"
        )),
    )
        .into_response()
}

/// Logout errors, which the reference sends without cache headers.
fn error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({"error":error,"error_description":description})),
    )
        .into_response()
}

fn invalid_grant(description: &str) -> Response {
    error(StatusCode::BAD_REQUEST, "invalid_grant", description)
}

fn client_error(error_code: &str) -> Response {
    error(
        StatusCode::UNAUTHORIZED,
        error_code,
        "Invalid client or Invalid client credentials",
    )
}

/// Why a logout request's realm could not be used.
enum RealmError {
    Invalid,
    Missing,
    Unavailable,
}

impl IntoResponse for RealmError {
    fn into_response(self) -> Response {
        match self {
            Self::Invalid => page(StatusCode::BAD_REQUEST, "Invalid request."),
            Self::Missing => page(StatusCode::NOT_FOUND, "Realm does not exist."),
            Self::Unavailable => unavailable(),
        }
    }
}

async fn realm_id(state: &OidcState, realm: &str) -> Result<String, RealmError> {
    if !valid_realm(realm) {
        return Err(RealmError::Invalid);
    }
    state
        .storage
        .realm_id_by_name(realm)
        .await
        .map_err(|_| RealmError::Unavailable)?
        .ok_or(RealmError::Missing)
}

/// Handles `POST /logout`; without a refresh token it is a browser logout.
pub(super) async fn post(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    form: Result<Form<Vec<(String, String)>>, FormRejection>,
) -> Response {
    let Ok(Form(pairs)) = form else {
        return page(StatusCode::BAD_REQUEST, "Invalid request.");
    };
    let mut fields = BTreeMap::new();
    for (name, value) in pairs {
        if fields.insert(name, value).is_some() {
            return page(StatusCode::BAD_REQUEST, "Invalid request.");
        }
    }
    let Some(refresh_token) = fields.remove("refresh_token").map(Zeroizing::new) else {
        return browser(state, realm, fields).await;
    };
    let realm_id = match realm_id(&state, &realm).await {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let credentials = match client_auth::parse(
        &headers,
        fields.remove("client_id"),
        fields.remove("client_secret").map(Zeroizing::new),
    ) {
        Ok(credentials) => credentials,
        Err(InvalidClientAuthentication::Missing) => return client_error("invalid_client"),
        Err(InvalidClientAuthentication::Malformed) => {
            return invalid_client(headers.contains_key(header::AUTHORIZATION));
        }
    };
    let client = match state.client_auth.authenticate(&realm_id, credentials).await {
        Ok(ClientAuthResult::Authenticated(client)) => client,
        Ok(ClientAuthResult::Unknown) => return client_error("invalid_client"),
        Ok(ClientAuthResult::Unauthorized) => return client_error("unauthorized_client"),
        Err(_) => return unavailable(),
    };
    if client.bearer_only {
        return client_auth::bearer_only_refused();
    }
    let claims = match verified_refresh(&state, &realm, &refresh_token).await {
        Ok(Some(claims)) => claims,
        Ok(None) => return invalid_grant("Invalid refresh token"),
        Err(_) => return unavailable(),
    };
    if claims.azp != client.client_id {
        return invalid_grant(
            "Invalid refresh token. Token client and authorized client don't match",
        );
    }
    match state
        .storage
        .logout_with_refresh_token(
            &realm_id,
            &client.client_id,
            client.revision,
            &digest(&claims.jti),
        )
        .await
    {
        Ok(RefreshLogout::Ended) => (
            StatusCode::NO_CONTENT,
            [(header::CACHE_CONTROL, "no-cache")],
        )
            .into_response(),
        Ok(RefreshLogout::UnknownToken) => invalid_grant("Invalid refresh token"),
        Err(_) => unavailable(),
    }
}

/// Handles `GET /logout`, RP-initiated logout.
pub(super) async fn get(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    browser(state, realm, params).await
}

/// Verifies an ID token hint against this realm's issuer.
async fn verified_hint(
    state: &OidcState,
    realm: &str,
    hint: &str,
) -> Result<Option<VerifiedIdToken>, ()> {
    if hint.len() > 8192 {
        return Ok(None);
    }
    let permit = Arc::clone(&state.signing_slots)
        .try_acquire_owned()
        .map_err(|_| ())?;
    let signer = Arc::clone(&state.signer);
    let hint = hint.to_owned();
    let claims = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        signer.verify_id_token(&hint)
    })
    .await
    .map_err(|_| ())?;
    let issuer = format!("{}/realms/{realm}", state.issuer_base.trim_end_matches('/'));
    Ok(claims.ok().filter(|claims| claims.iss == issuer))
}

async fn browser(state: OidcState, realm: String, params: BTreeMap<String, String>) -> Response {
    let realm_id = match realm_id(&state, &realm).await {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let hint = match params.get("id_token_hint") {
        None => None,
        Some(hint) => match verified_hint(&state, &realm, hint).await {
            Ok(Some(claims)) => Some(claims),
            Ok(None) => return page(StatusCode::BAD_REQUEST, "Invalid parameter: id_token_hint"),
            Err(()) => return unavailable(),
        },
    };
    let client = match (
        hint.as_ref().map(|claims| &claims.aud),
        params.get("client_id"),
    ) {
        (Some(audience), Some(client)) if audience != client => {
            return page(StatusCode::BAD_REQUEST, "Invalid parameter: client_id");
        }
        (Some(audience), _) => Some(audience.clone()),
        (None, client) => client.cloned(),
    };
    let redirect = match params.get("post_logout_redirect_uri") {
        None => None,
        Some(uri) => {
            let allowed = match &client {
                Some(client) => match state.storage.post_logout_rules(&realm_id, client).await {
                    Ok(Some(rules)) => {
                        let server = state.issuer_base.trim_end_matches('/');
                        rules.redirect_uris.iter().any(|registered| {
                            resolve_redirect(registered, rules.root_url.as_deref(), server)
                                .is_some_and(|resolved| redirect_matches(&resolved, uri))
                        })
                    }
                    Ok(None) => false,
                    Err(_) => return unavailable(),
                },
                None => false,
            };
            match Url::parse(uri) {
                Ok(url) if allowed => Some(url),
                _ => return page(StatusCode::BAD_REQUEST, "Invalid redirect uri"),
            }
        }
    };
    if let Some(VerifiedIdToken {
        sid: Some(sid),
        sub,
        ..
    }) = &hint
        && state
            .storage
            .logout_session(&realm_id, sid, sub)
            .await
            .is_err()
    {
        return unavailable();
    }
    let mut response = match redirect {
        Some(mut url) => {
            if let Some(value) = params.get("state") {
                url.query_pairs_mut().append_pair("state", value);
            }
            (
                StatusCode::FOUND,
                [
                    (header::LOCATION, url.to_string()),
                    (header::CACHE_CONTROL, "no-cache".to_owned()),
                ],
            )
                .into_response()
        }
        None if hint.is_some() => page(StatusCode::OK, "You are logged out."),
        None => page(StatusCode::OK, "You have no active session to log out."),
    };
    if hint.is_some() {
        for value in sso_cookies(&state.path_prefix, &realm, None) {
            if let Ok(value) = HeaderValue::from_str(&value) {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
        }
    }
    response
}
