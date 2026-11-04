//! Client-scoped browser access to token and userinfo responses.

use std::collections::BTreeMap;

use axum::Json;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use url::Url;
use zeroize::Zeroizing;

use super::{OidcState, valid_realm, verified_access};
use crate::client_auth::{self, ClientCredentials};

fn single_header(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn canonical_origin(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.origin().ascii_serialization() == value
}

fn vary(response: &mut Response) {
    response
        .headers_mut()
        .append(header::VARY, HeaderValue::from_static("Origin"));
}

fn forbidden() -> Response {
    let mut response = (
        StatusCode::FORBIDDEN,
        Json(json!({"error":"Invalid origin"})),
    )
        .into_response();
    vary(&mut response);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn allow(response: &mut Response, origin: &str) {
    if let Ok(value) = HeaderValue::from_str(origin) {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }
}

/// Handles browser preflight and adds CORS headers only for the bound client.
pub(super) async fn handle(
    State(state): State<OidcState>,
    Path(path): Path<BTreeMap<String, String>>,
    request: Request,
    next: Next,
) -> Response {
    if !request.headers().contains_key(header::ORIGIN) {
        let mut response = next.run(request).await;
        vary(&mut response);
        return response;
    }
    let Some(origin) = single_header(request.headers(), header::ORIGIN)
        .filter(|value| canonical_origin(value))
        .map(str::to_owned)
    else {
        return forbidden();
    };
    let Some(realm) = path.get("realm").filter(|value| valid_realm(value)) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let realm_id = match state.storage.realm_id_by_name(realm).await {
        Ok(Some(id)) => id,
        Ok(None) => return StatusCode::FORBIDDEN.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let is_form = !request
        .uri()
        .path()
        .ends_with("/protocol/openid-connect/userinfo");
    if request.method() == Method::OPTIONS {
        let method = single_header(request.headers(), header::ACCESS_CONTROL_REQUEST_METHOD);
        let valid_method = if is_form {
            method == Some("POST")
        } else {
            matches!(method, Some("GET" | "HEAD"))
        };
        if !valid_method {
            return forbidden();
        }
        let mut response = StatusCode::OK.into_response();
        allow(&mut response, &origin);
        response.headers_mut().insert(
            header::VARY,
            HeaderValue::from_static(
                "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
            ),
        );
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static(if is_form {
                "POST, OPTIONS"
            } else {
                "GET, HEAD, OPTIONS"
            }),
        );
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Authorization, Content-Type"),
        );
        return response;
    }
    let (request, client_id) = if is_form {
        let (parts, body) = request.into_parts();
        let body = match to_bytes(body, 16 * 1024).await {
            Ok(body) => body,
            Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        };
        let mut id = None;
        let mut secret = None;
        let mut ambiguous = false;
        for (name, value) in url::form_urlencoded::parse(&body) {
            if name == "client_id" {
                if id.replace(value.into_owned()).is_some() {
                    ambiguous = true;
                }
            } else if name == "client_secret"
                && secret.replace(Zeroizing::new(value.into_owned())).is_some()
            {
                ambiguous = true;
            }
        }
        let id = if ambiguous {
            None
        } else {
            match client_auth::parse(&parts.headers, id, secret) {
                Ok(
                    ClientCredentials::Public(id)
                    | ClientCredentials::Confidential { client_id: id, .. },
                ) => Some(id),
                Err(_) => None,
            }
        };
        (Request::from_parts(parts, Body::from(body)), id)
    } else {
        let bearer = single_header(request.headers(), header::AUTHORIZATION)
            .and_then(|value| value.strip_prefix("Bearer "));
        let id = match bearer {
            Some(token) => match verified_access(&state, realm, token).await {
                Ok(Some(claims)) => Some(claims.azp),
                Ok(None) => None,
                Err(()) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            },
            None => None,
        };
        (request, id)
    };
    let permitted = if let Some(id) = client_id {
        match state
            .storage
            .client_web_origin_allowed(&realm_id, &id, &origin)
            .await
        {
            Ok(value) => value,
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        false
    };
    if !permitted {
        return forbidden();
    }
    let mut response = next.run(request).await;
    vary(&mut response);
    allow(&mut response, &origin);
    response
}

/// Allows cross-origin reads of public discovery and signing-key metadata.
pub(super) async fn metadata(request: Request, next: Next) -> Response {
    let origin = single_header(request.headers(), header::ORIGIN).map(str::to_owned);
    if request.headers().contains_key(header::ORIGIN) && origin.is_none() {
        return forbidden();
    }
    if request.method() == Method::OPTIONS {
        let mut response = StatusCode::OK.into_response();
        if let Some(origin) = origin {
            allow(&mut response, &origin);
            vary(&mut response);
            response.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET"),
            );
            response.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Origin, X-Requested-With, Accept, Access-Control-Request-Method, Access-Control-Request-Headers, DPoP, Content-Type, Authorization"));
        }
        return response;
    }
    let mut response = next.run(request).await;
    vary(&mut response);
    if let Some(origin) = origin {
        allow(&mut response, &origin);
    }
    response
}
