//! HTTP management routes for the server lifecycle.

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;

/// Builds the management router. Readiness stays closed until the server can
/// serve authentication requests safely.
pub fn management_router() -> Router {
    Router::new()
        .route("/health/live", get(|| async { StatusCode::OK }))
        .route(
            "/health/ready",
            get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        )
}

pub mod oidc;

mod account;
pub mod account_console;
mod admin;
mod locale;
mod login_theme;
mod mail;
mod security_headers;

pub mod client_auth;
