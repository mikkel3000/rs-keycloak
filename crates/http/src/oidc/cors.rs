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

/// Request headers Keycloak's `Cors` builder allows on every preflight.
const ALLOWED_HEADERS: &str = "Origin, X-Requested-With, Accept, Access-Control-Request-Method, \
     Access-Control-Request-Headers, DPoP, Content-Type, Authorization";

/// Answers a preflight for any canonical origin, as the reference does.
///
/// Preflights cannot change state; origin registration is enforced on the
/// actual request, before any token processing.
fn preflight(origin: &str, methods: &'static str) -> Response {
    let mut response = StatusCode::OK.into_response();
    allow(&mut response, origin);
    let headers = response.headers_mut();
    headers.insert(
        header::VARY,
        HeaderValue::from_static(
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
        ),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(methods),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(ALLOWED_HEADERS),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("3600"),
    );
    response
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
        return preflight(
            &origin,
            if is_form {
                "POST, OPTIONS"
            } else {
                "GET, HEAD, OPTIONS"
            },
        );
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
        // The reference allows every origin until a verified token names the
        // client whose registered origins apply; the handler then answers 401.
        let Some(id) = id else {
            let mut response = next.run(request).await;
            vary(&mut response);
            allow(&mut response, &origin);
            expose_userinfo_headers(&mut response);
            return response;
        };
        (request, Some(id))
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
    if !is_form {
        expose_userinfo_headers(&mut response);
    }
    response
}

/// Exposes the headers the reference userinfo endpoint lists for scripts.
fn expose_userinfo_headers(response: &mut Response) {
    let exposed = if response.headers().contains_key(header::WWW_AUTHENTICATE) {
        "Access-Control-Allow-Methods, WWW-Authenticate"
    } else {
        "Access-Control-Allow-Methods"
    };
    response.headers_mut().insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(exposed),
    );
}

/// Allows cross-origin reads of public discovery and signing-key metadata.
pub(super) async fn metadata(request: Request, next: Next) -> Response {
    let origin = single_header(request.headers(), header::ORIGIN).map(str::to_owned);
    if request.headers().contains_key(header::ORIGIN) && origin.is_none() {
        return forbidden();
    }
    if request.method() == Method::OPTIONS {
        return match origin {
            Some(origin) => preflight(&origin, "GET"),
            None => StatusCode::OK.into_response(),
        };
    }
    let mut response = next.run(request).await;
    vary(&mut response);
    if let Some(origin) = origin {
        allow(&mut response, &origin);
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::get;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::{metadata, preflight};

    const CORS_HEADERS: [&str; 4] = [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
    ];

    /// Pinned Keycloak observations for `cors/{origin}/{endpoint}/{case}`.
    fn observations() -> Vec<(String, String, Value)> {
        let recorded: Value = serde_json::from_str(include_str!(
            "../../../../tests/reference/token-observations.json"
        ))
        .expect("reference observations parse");
        let cases: Vec<_> = recorded["observations"]
            .as_object()
            .expect("observations object")
            .iter()
            .filter_map(|(key, value)| {
                let mut parts = key.strip_prefix("cors/")?.split('/').skip(1);
                Some((
                    parts.next()?.to_owned(),
                    parts.next()?.to_owned(),
                    value.clone(),
                ))
            })
            .collect();
        assert!(!cases.is_empty(), "reference has no CORS observations");
        cases
    }

    fn assert_matches(name: &str, headers: &axum::http::HeaderMap, expected: &Value) {
        for header in CORS_HEADERS {
            assert_eq!(
                headers.get(header).and_then(|value| value.to_str().ok()),
                expected["cors"][header].as_str(),
                "{name}: {header}",
            );
        }
    }

    #[test]
    fn preflight_matches_reference_for_every_origin() {
        for (endpoint, case, expected) in observations() {
            if case != "preflight" {
                continue;
            }
            let methods = match endpoint.as_str() {
                "token" => "POST, OPTIONS",
                "userinfo" => "GET, HEAD, OPTIONS",
                _ => "GET",
            };
            let origin = expected["cors"]["Access-Control-Allow-Origin"]
                .as_str()
                .expect("reference preflight echoes origin");
            let response = preflight(origin, methods);
            assert_eq!(response.status().as_u16(), expected["status"], "{endpoint}");
            assert_matches(&endpoint, response.headers(), &expected);
        }
    }

    #[tokio::test]
    async fn metadata_routes_match_reference_for_any_origin() {
        let app = Router::new()
            .route(
                "/meta",
                get(|| async { StatusCode::OK }).options(|| async { StatusCode::OK }),
            )
            .layer(axum::middleware::from_fn(metadata));
        for (endpoint, case, expected) in observations() {
            if !matches!(endpoint.as_str(), "certs" | "discovery") {
                continue;
            }
            let method = if case == "preflight" {
                Method::OPTIONS
            } else {
                Method::GET
            };
            let origin = expected["cors"]["Access-Control-Allow-Origin"]
                .as_str()
                .expect("reference echoes metadata origin");
            let request = Request::builder()
                .method(method)
                .uri("/meta")
                .header("Origin", origin)
                .header("Access-Control-Request-Method", "GET")
                .body(Body::empty())
                .expect("request builds");
            let response = app.clone().oneshot(request).await.expect("infallible");
            assert_eq!(
                response.status().as_u16(),
                expected["status"],
                "{endpoint}/{case}"
            );
            assert_matches(&format!("{endpoint}/{case}"), response.headers(), &expected);
        }
    }
}
