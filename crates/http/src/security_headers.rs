//! Keycloak's default browser security headers, recorded in
//! `tests/reference/account-console-observations.json`.
//!
//! Only the account console, its resources and the session iframes send
//! them; other routes keep the headers their own recordings show.

use axum::http::{HeaderMap, HeaderName, HeaderValue, header};

/// What a response is, which decides its framing headers.
#[derive(Clone, Copy)]
pub(crate) enum Framing {
    /// An HTML page: framed only by its own origin.
    Page,
    /// A JSON body: framed only by its own origin, no content policy.
    Json,
    /// An iframe any origin may embed.
    Iframe,
    /// Scripts, styles, images and empty responses.
    Plain,
}

/// Adds the headers every response gets, then those of its framing.
pub(crate) fn apply(headers: &mut HeaderMap, framing: Framing) {
    let mut set = |name: HeaderName, value: &'static str| {
        headers.insert(name, HeaderValue::from_static(value));
    };
    set(header::REFERRER_POLICY, "no-referrer");
    set(
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=31536000; includeSubDomains",
    );
    set(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(HeaderName::from_static("x-robots-tag"), "none");
    match framing {
        Framing::Page => {
            set(
                header::CONTENT_SECURITY_POLICY,
                "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
            );
            set(header::X_FRAME_OPTIONS, "SAMEORIGIN");
        }
        Framing::Json => set(header::X_FRAME_OPTIONS, "SAMEORIGIN"),
        Framing::Iframe => set(
            header::CONTENT_SECURITY_POLICY,
            "frame-src 'self'; object-src 'none';",
        ),
        Framing::Plain => {}
    }
}
