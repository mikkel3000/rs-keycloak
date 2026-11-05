//! Client-authenticated revocation with Keycloak's token ownership rules.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rs_keycloak_storage_postgres::AccessTokenStatus;
use serde_json::json;
use zeroize::Zeroizing;

use crate::client_auth::{self, ClientAuthResult, InvalidClientAuthentication};

use super::{
    OidcState, digest, invalid_client, unauthorized_client, unavailable, unknown_client,
    valid_realm, verified_access, verified_refresh,
};

fn error(status: StatusCode, error: &'static str, description: &'static str) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({"error":error,"error_description":description})),
    )
        .into_response()
}

fn invalid_token() -> Response {
    error(StatusCode::OK, "invalid_token", "Invalid token")
}

pub(super) async fn handle(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    form: Result<Form<Vec<(String, String)>>, FormRejection>,
) -> Response {
    let Ok(Form(pairs)) = form else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid request",
        );
    };
    let mut fields = BTreeMap::new();
    for (name, value) in pairs {
        if fields.insert(name, value).is_some() {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "duplicated parameter",
            );
        }
    }
    if !valid_realm(&realm) {
        return error(StatusCode::BAD_REQUEST, "invalid_request", "Invalid realm");
    }
    let realm_id = match state.storage.realm_id_by_name(&realm).await {
        Ok(Some(id)) => id,
        Ok(None) => return error(StatusCode::FORBIDDEN, "access_denied", "Realm not enabled"),
        Err(_) => return unavailable(),
    };
    let credentials = match client_auth::parse(
        &headers,
        fields.remove("client_id"),
        fields.remove("client_secret").map(Zeroizing::new),
    ) {
        Ok(credentials) => credentials,
        Err(InvalidClientAuthentication::Missing) => return unknown_client(),
        Err(InvalidClientAuthentication::Malformed) => {
            return invalid_client(headers.contains_key(header::AUTHORIZATION));
        }
    };
    let client = match state.client_auth.authenticate(&realm_id, credentials).await {
        Ok(ClientAuthResult::Authenticated(client)) => client,
        Ok(ClientAuthResult::Unknown) => return unknown_client(),
        Ok(ClientAuthResult::Unauthorized) => return unauthorized_client(),
        Err(_) => return unavailable(),
    };
    if client.bearer_only {
        return client_auth::bearer_only_refused();
    }
    let Some(token) = fields.remove("token").map(Zeroizing::new) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Token not provided",
        );
    };
    if token.len() > 8192 {
        return invalid_token();
    }
    let permit = match Arc::clone(&state.signing_slots).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return unavailable(),
    };
    let signer = Arc::clone(&state.signer);
    let candidate = Zeroizing::new(token.to_string());
    let token_type = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        signer.verify_token_type(&candidate)
    })
    .await;
    let token_type = match token_type {
        Ok(Ok(token_type)) => token_type,
        Ok(Err(_)) => return invalid_token(),
        Err(_) => return unavailable(),
    };
    let refresh = match token_type.as_str() {
        "Bearer" => false,
        "Refresh" => true,
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "unsupported_token_type",
                "Unsupported token type",
            );
        }
    };
    let claims = if refresh {
        verified_refresh(&state, &realm, &token).await
    } else {
        verified_access(&state, &realm, &token).await
    };
    let claims = match claims {
        Ok(Some(claims)) => claims,
        Ok(None) => return invalid_token(),
        Err(_) => return unavailable(),
    };
    if claims.azp != client.client_id {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Unmatching clients",
        );
    }
    if refresh {
        match state
            .storage
            .revoke_refresh_token(
                &realm_id,
                &client.client_id,
                client.revision,
                &digest(&claims.jti),
            )
            .await
        {
            Ok(true) => (),
            Ok(false) => return invalid_token(),
            Err(_) => return unavailable(),
        }
    } else {
        match state
            .storage
            .active_access_token(
                &realm_id,
                &client.client_id,
                claims.sid.as_deref(),
                &claims.sub,
                &digest(&claims.jti),
            )
            .await
        {
            Ok(AccessTokenStatus::Active(_) | AccessTokenStatus::ServiceAccount(_)) => (),
            Ok(
                AccessTokenStatus::ClientNotFound
                | AccessTokenStatus::Revoked
                | AccessTokenStatus::SessionNotFound,
            ) => {
                return invalid_token();
            }
            Err(_) => return unavailable(),
        }
        let Ok(expiry) = i64::try_from(claims.exp) else {
            return invalid_token();
        };
        if state
            .storage
            .revoke_access_token(
                &realm_id,
                &client.client_id,
                client.revision,
                claims.sid.as_deref(),
                &claims.sub,
                &digest(&claims.jti),
                expiry,
            )
            .await
            .is_err()
        {
            return unavailable();
        }
    }
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
    )
        .into_response()
}
