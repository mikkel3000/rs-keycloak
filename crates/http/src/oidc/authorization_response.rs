//! Authorization responses using the mode bound to the login request.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use rs_keycloak_storage_postgres::AuthorizationRedirect;
use url::Url;

use super::random_token;

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Sends an authorization code with the session it belongs to.
pub(super) fn build(
    redirect: AuthorizationRedirect,
    code: &str,
    session_state: &str,
    issuer: &str,
) -> Result<Response, ()> {
    respond(
        &redirect,
        vec![
            ("code", code),
            ("session_state", session_state),
            ("iss", issuer),
        ],
    )
}

/// Sends an OAuth error, such as `login_required`, to a validated redirect.
pub(super) fn error(
    redirect: AuthorizationRedirect,
    error: &str,
    issuer: &str,
) -> Result<Response, ()> {
    respond(&redirect, vec![("error", error), ("iss", issuer)])
}

fn respond<'a>(
    redirect: &'a AuthorizationRedirect,
    mut pairs: Vec<(&'a str, &'a str)>,
) -> Result<Response, ()> {
    let mut url = Url::parse(&redirect.redirect_uri).map_err(|_| ())?;
    if let Some(state) = &redirect.state {
        pairs.push(("state", state));
    }
    let mut response = match redirect.response_mode.as_str() {
        "query" | "fragment" => {
            if redirect.response_mode == "query" {
                url.query_pairs_mut().extend_pairs(pairs);
            } else {
                let encoded = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(pairs)
                    .finish();
                url.set_fragment(Some(&encoded));
            }
            let location = HeaderValue::from_str(url.as_str()).map_err(|_| ())?;
            (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
        }
        "form_post" => {
            let nonce = random_token();
            let mut fields = String::new();
            for (name, value) in pairs {
                fields.push_str(&format!(
                    "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
                    escape(value)
                ));
            }
            let html = format!(
                "<!doctype html><html><head><meta charset=\"utf-8\"><title>Continue signing in</title></head><body><form method=\"post\" action=\"{}\">{fields}<noscript><button type=\"submit\">Continue</button></noscript></form><script nonce=\"{nonce}\">document.forms[0].submit();</script></body></html>",
                escape(&redirect.redirect_uri),
            );
            let policy = format!(
                "default-src 'none'; script-src 'nonce-{nonce}'; form-action {}; frame-ancestors 'none'; base-uri 'none'",
                url.origin().ascii_serialization()
            );
            let mut response = Html(html).into_response();
            response.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_str(&policy).map_err(|_| ())?,
            );
            response
        }
        _ => return Err(()),
    };
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    Ok(response)
}
