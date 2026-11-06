//! Client-credentials grant for confidential clients with service accounts.
//!
//! Follows the pinned ClientCredentialsGrantType: tokens carry no session ID,
//! no refresh token is issued, and an ID token is added only for `openid`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use rs_keycloak_crypto::signing::{IdTokenClaims, RealmAccess, TokenClaims, UserClaims};
use rs_keycloak_storage_postgres::ServiceAccountGrant;
use serde_json::json;

use crate::client_auth::AuthenticatedClient;

use super::{
    OidcState, has_openid_scope, random_token, resource_access, token_lifespan, unavailable,
};

fn error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({"error":error, "error_description":description})),
    )
        .into_response()
}

fn unauthorized(description: &str) -> Response {
    error(StatusCode::UNAUTHORIZED, "unauthorized_client", description)
}

/// Returns the granted scope string, or `None` if any value is not grantable.
/// Only `openid` is grantable until client scopes are implemented.
fn granted_scope(requested: Option<&str>) -> Option<&'static str> {
    let mut openid = false;
    for value in requested
        .unwrap_or_default()
        .split(' ')
        .filter(|v| !v.is_empty())
    {
        if value != "openid" {
            return None;
        }
        openid = true;
    }
    Some(if openid { "openid" } else { "" })
}

/// Issues service-account tokens to an authenticated client.
pub(super) async fn grant(
    state: &OidcState,
    realm: &str,
    realm_id: &str,
    client: AuthenticatedClient,
    scope: Option<&str>,
) -> Response {
    let Some(revision) = client.revision else {
        return unauthorized("Public client not allowed to retrieve service account");
    };
    let account = match state
        .storage
        .service_account_grant(realm_id, &client.client_id, revision)
        .await
    {
        Ok(ServiceAccountGrant::Granted(account)) => account,
        Ok(ServiceAccountGrant::NotEnabled) => {
            return unauthorized("Client not enabled to retrieve service account");
        }
        Ok(ServiceAccountGrant::MissingUser) => {
            return error(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                "The associated service account for the client does not exist",
            );
        }
        Ok(ServiceAccountGrant::UserDisabled(username)) => {
            return error(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                &format!("User '{username}' disabled"),
            );
        }
        Err(_) => return unavailable(),
    };
    let Some(granted) = granted_scope(scope) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            &format!("Invalid scopes: {}", scope.unwrap_or_default()),
        );
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return unavailable();
    };
    let now = now.as_secs();
    let Some(lifespan) = token_lifespan(state, realm_id).await else {
        return unavailable();
    };
    let Ok(permit) = Arc::clone(&state.signing_slots).try_acquire_owned() else {
        return unavailable();
    };
    let Ok(roles) = state
        .storage
        .effective_roles(realm_id, &account.user_id)
        .await
    else {
        return unavailable();
    };
    let issuer = format!("{}/realms/{realm}", state.issuer_base.trim_end_matches('/'));
    let signer = Arc::clone(&state.signer);
    let client_id = client.client_id;
    let tokens = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let jti = random_token();
        let access = signer.sign(&TokenClaims {
            iss: &issuer,
            sub: &account.user_id,
            aud: &client_id,
            iat: now,
            exp: now + lifespan,
            jti: &jti,
            azp: &client_id,
            sid: None,
            scope: granted,
            realm_access: Some(RealmAccess {
                roles: &roles.realm,
            }),
            resource_access: resource_access(&roles),
            user: UserClaims::default(),
        })?;
        let id = if has_openid_scope(granted) {
            Some(signer.sign_id_token(&IdTokenClaims {
                iss: &issuer,
                sub: &account.user_id,
                aud: &client_id,
                iat: now,
                exp: now + lifespan,
                auth_time: None,
                nonce: None,
                sid: None,
                user: UserClaims::default(),
            })?)
        } else {
            None
        };
        Ok::<_, rs_keycloak_crypto::signing::SigningError>((access, id))
    })
    .await;
    let Ok(Ok((access_token, id_token))) = tokens else {
        return unavailable();
    };
    let mut body = json!({
        "access_token": access_token,
        "expires_in": lifespan,
        "refresh_expires_in": 0,
        "token_type": "Bearer",
        "not-before-policy": 0,
        "scope": granted,
    });
    if let Some(id_token) = id_token {
        body["id_token"] = json!(id_token);
    }
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::granted_scope;

    #[test]
    fn only_openid_is_grantable() {
        assert_eq!(granted_scope(None), Some(""));
        assert_eq!(granted_scope(Some("")), Some(""));
        assert_eq!(granted_scope(Some("openid")), Some("openid"));
        assert_eq!(granted_scope(Some("openid  openid")), Some("openid"));
        assert_eq!(granted_scope(Some("openid profile")), None);
        assert_eq!(granted_scope(Some("unknown-scope")), None);
    }
}
