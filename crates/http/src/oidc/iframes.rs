//! The iframes keycloak-js loads: the third-party cookie check and the
//! login status iframe with its origin check.
//!
//! Follows `tests/reference/account-console-observations.json`. The pages
//! are Keycloak's own; the login status page is the reference's rendering
//! for a secure context, which an HTTPS issuer always is.

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rs_keycloak_protocols::client_urls::resolve_redirect;
use serde::Deserialize;

use crate::account_console::{issuer_origin, realm_does_not_exist, resource_version};
use crate::oidc::OidcState;
use crate::security_headers::{self, Framing};

const STEP1: &str = include_str!("3p-cookies-step1.html");
const STEP2: &str = include_str!("3p-cookies-step2.html");
const LOGIN_STATUS: &str = include_str!("login-status-iframe.html");

pub(crate) fn routes() -> Router<OidcState> {
    let base = "/realms/{realm}/protocol/openid-connect";
    Router::new()
        .route(
            &format!("{base}/3p-cookies/step1.html"),
            get(|state, realm, query| page(state, realm, query, STEP1)),
        )
        .route(
            &format!("{base}/3p-cookies/step2.html"),
            get(|state, realm, query| page(state, realm, query, STEP2)),
        )
        .route(
            &format!("{base}/login-status-iframe.html"),
            get(|state, realm, query| page(state, realm, query, LOGIN_STATUS)),
        )
        .route(&format!("{base}/login-status-iframe.html/init"), get(init))
}

#[derive(Deserialize)]
struct VersionQuery {
    version: Option<String>,
}

/// An iframe page. With the current `version` it may be cached like a
/// resource; without one it is never stored; another version is unknown.
async fn page(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    Query(query): Query<VersionQuery>,
    body: &'static str,
) -> Response {
    match state.storage.realm_id_by_name(&realm).await {
        Ok(Some(_)) => {}
        Ok(None) => return realm_does_not_exist(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    let cache = match query.version.as_deref() {
        None => "no-cache, must-revalidate, no-transform, no-store",
        Some(version) if version == resource_version() => "no-cache",
        Some(_) => return plain(StatusCode::NOT_FOUND),
    };
    let mut response = (
        [
            (header::CONTENT_TYPE, "text/html;charset=utf-8"),
            (header::CACHE_CONTROL, cache),
        ],
        body,
    )
        .into_response();
    security_headers::apply(response.headers_mut(), Framing::Iframe);
    response
}

#[derive(Deserialize)]
struct InitQuery {
    client_id: Option<String>,
    origin: Option<String>,
}

/// Allows the login status iframe to answer a client at an origin: the
/// server's own, or one of the enabled client's web origins, where `+`
/// stands for its redirect URI origins and `*` for any.
async fn init(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    Query(query): Query<InitQuery>,
) -> Response {
    let (Some(client_id), Some(origin)) = (query.client_id, query.origin) else {
        return plain(StatusCode::FORBIDDEN);
    };
    let realm_id = match state.storage.realm_id_by_name(&realm).await {
        Ok(Some(realm_id)) => realm_id,
        Ok(None) => return plain(StatusCode::FORBIDDEN),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let client = match state.storage.clients(&realm_id, Some(&client_id)).await {
        Ok(clients) => clients.into_iter().find(|client| client.enabled),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let Some(client) = client else {
        return plain(StatusCode::FORBIDDEN);
    };
    let server = state.issuer_base.trim_end_matches('/');
    let redirect_origins = || {
        client.redirect_uris.iter().filter_map(|registered| {
            resolve_redirect(registered, client.root_url.as_deref(), server)
                .and_then(|resolved| url::Url::parse(&resolved).ok())
                .map(|url| url.origin().ascii_serialization())
        })
    };
    let allowed = origin == issuer_origin(&state.issuer_base)
        || client
            .web_origins
            .iter()
            .any(|allowed| match allowed.as_str() {
                "*" => true,
                "+" => redirect_origins().any(|own| own == origin),
                exact => exact == origin,
            });
    plain(if allowed {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::FORBIDDEN
    })
}

fn plain(status: StatusCode) -> Response {
    let mut response = status.into_response();
    security_headers::apply(response.headers_mut(), Framing::Plain);
    response
}
