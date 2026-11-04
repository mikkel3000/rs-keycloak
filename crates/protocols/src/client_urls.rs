//! Validation of client redirect URIs and browser web origins.
//!
//! Plain HTTP is accepted only for loopback hosts, and only when the caller
//! allows it for local development.

use url::Url;

fn loopback(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

/// Checks an exact redirect URI: HTTPS without credentials, fragment, or
/// `code`/`state` query parameters.
pub fn validate_redirect_uri(uri: &str, allow_loopback_http: bool) -> Result<(), &'static str> {
    if uri.len() > 2048 {
        return Err("Redirect URI is too long");
    }
    let redirect = Url::parse(uri).map_err(|_| "Redirect URI is invalid")?;
    if redirect
        .query_pairs()
        .any(|(key, _)| key == "code" || key == "state")
    {
        return Err("Redirect URI must not contain code or state query parameters");
    }
    let http_allowed = allow_loopback_http && loopback(&redirect);
    if !(redirect.scheme() == "https" || (redirect.scheme() == "http" && http_allowed))
        || redirect.host_str().is_none()
        || !redirect.username().is_empty()
        || redirect.password().is_some()
        || redirect.fragment().is_some()
    {
        return Err(
            "Redirect URI must use HTTPS without credentials or a fragment; HTTP is allowed only for local development",
        );
    }
    Ok(())
}

/// Checks a web origin in its exact serialized form, such as
/// `https://app.example`, with no path, wildcard, or `null`.
pub fn validate_web_origin(origin: &str, allow_loopback_http: bool) -> Result<(), &'static str> {
    if origin.len() > 2048 {
        return Err("Web origin is too long");
    }
    let parsed = Url::parse(origin).map_err(|_| "Web origin is invalid")?;
    let http_allowed = allow_loopback_http && loopback(&parsed);
    if !(parsed.scheme() == "https" || (parsed.scheme() == "http" && http_allowed))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.origin().ascii_serialization() != origin
    {
        return Err(
            "Web origin must be a canonical HTTPS origin; loopback HTTP requires local development",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_redirect_uri, validate_web_origin};

    #[test]
    fn redirect_uris_require_https_outside_local_loopback() {
        assert!(validate_redirect_uri("https://app.example/cb?x=1", false).is_ok());
        assert!(validate_redirect_uri("http://localhost:8080/cb", true).is_ok());
        assert!(validate_redirect_uri("http://localhost:8080/cb", false).is_err());
        assert!(validate_redirect_uri("http://app.example/cb", true).is_err());
        assert!(validate_redirect_uri("https://user@app.example/cb", false).is_err());
        assert!(validate_redirect_uri("https://app.example/cb#x", false).is_err());
        assert!(validate_redirect_uri("https://app.example/cb?state=1", false).is_err());
    }

    #[test]
    fn web_origins_must_be_canonical() {
        assert!(validate_web_origin("https://app.example", false).is_ok());
        assert!(validate_web_origin("http://127.0.0.1:3000", true).is_ok());
        for bad in [
            "*",
            "null",
            "https://app.example/",
            "https://app.example/path",
            "HTTPS://app.example",
        ] {
            assert!(validate_web_origin(bad, false).is_err(), "{bad}");
        }
    }
}
