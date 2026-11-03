//! Authenticated token introspection against current PostgreSQL session state.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::client_auth::{self, ClientAuthResult};

use super::{
    OidcState, digest, unavailable, unknown_client, valid_realm, verified_access, verified_refresh,
};

fn reply(status: StatusCode, body: Value) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response()
}

fn error(status: StatusCode, code: &'static str, description: &'static str) -> Response {
    reply(
        status,
        json!({"error":code, "error_description":description}),
    )
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
            "Invalid request.",
        );
    };
    let mut fields = BTreeMap::new();
    for (key, value) in pairs {
        if fields.insert(key, value).is_some() {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "duplicated parameter",
            );
        }
    }
    if !valid_realm(&realm) {
        return error(StatusCode::BAD_REQUEST, "invalid_request", "Invalid realm.");
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
        Err(_) => {
            return error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Client authentication failed.",
            );
        }
    };
    let client = match state.client_auth.authenticate(&realm_id, credentials).await {
        Ok(ClientAuthResult::Authenticated(client)) => client,
        Ok(ClientAuthResult::Unknown) => return unknown_client(),
        Ok(ClientAuthResult::Unauthorized) => {
            return error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Client authentication failed.",
            );
        }
        Err(_) => return unavailable(),
    };
    if client.revision.is_none() {
        return error(
            StatusCode::FORBIDDEN,
            "invalid_request",
            "Client not allowed.",
        );
    }
    let Some(token) = fields.remove("token").map(Zeroizing::new) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Token not provided.",
        );
    };
    let hint = fields.remove("token_type_hint");
    if hint
        .as_deref()
        .is_some_and(|hint| !matches!(hint, "access_token" | "refresh_token"))
    {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Unsupported token type.",
        );
    }
    let inactive = || reply(StatusCode::OK, json!({"active":false}));
    let refresh_claims = match verified_refresh(&state, &realm, &token).await {
        Ok(claims) => claims,
        Err(_) => return unavailable(),
    };
    if let Some(claims) = refresh_claims {
        if claims.azp != client.client_id {
            return inactive();
        }
        let grant = match state
            .storage
            .introspect_refresh_token(
                &realm_id,
                &client.client_id,
                client.revision,
                &digest(&claims.jti),
            )
            .await
        {
            Ok(Some(grant)) => grant,
            Ok(None) => return inactive(),
            Err(_) => return unavailable(),
        };
        if claims.sid != grant.grant.session.session_id || claims.sub != grant.grant.session.user_id
        {
            return inactive();
        }
        return reply(
            StatusCode::OK,
            json!({
                "active":true, "sub":grant.grant.session.user_id,
                "client_id":grant.grant.session.client_identifier,
                "username":grant.grant.session.username, "scope":grant.grant.scope,
                "exp":grant.expires_at, "sid":grant.grant.session.session_id,
                "token_type":"Refresh", "typ":"Refresh", "iss":claims.iss,
                "iat":claims.iat, "jti":claims.jti, "azp":claims.azp, "aud":claims.aud,
            }),
        );
    }
    if hint.as_deref() == Some("refresh_token") {
        return inactive();
    }
    let claims = match verified_access(&state, &realm, &token).await {
        Ok(Some(claims)) => claims,
        Ok(None) => return inactive(),
        Err(_) => return unavailable(),
    };
    if claims.aud != client.client_id {
        return inactive();
    }
    let session = match state
        .storage
        .introspect_access_token(
            &realm_id,
            &client.client_id,
            client.revision,
            &claims.sid,
            &claims.sub,
            &digest(&claims.jti),
        )
        .await
    {
        Ok(Some(session)) => session,
        Ok(None) => return inactive(),
        Err(_) => return unavailable(),
    };
    reply(
        StatusCode::OK,
        json!({
            "active":true, "iss":claims.iss, "sub":claims.sub, "aud":claims.aud,
            "iat":claims.iat, "exp":claims.exp, "jti":claims.jti,
            "azp":claims.azp, "client_id":client.client_id, "sid":claims.sid,
            "scope":claims.scope, "username":session.username, "token_type":"Bearer", "typ":"Bearer",
        }),
    )
}
