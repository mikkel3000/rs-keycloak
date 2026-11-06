//! Validation and matching of client redirect URIs, and validation of
//! browser web origins.
//!
//! Plain HTTP is accepted only for loopback hosts, and only when the caller
//! allows it for local development. Matching follows
//! `tests/reference/redirect-matching-observations.json`.

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

/// Checks a registered redirect URI: an exact URI as in
/// [`validate_redirect_uri`], optionally ending in `/*` to match everything
/// below it, or a path starting with `/` that resolves against the client's
/// root URL.
pub fn validate_redirect_pattern(uri: &str, allow_loopback_http: bool) -> Result<(), &'static str> {
    let base = uri.strip_suffix("/*").unwrap_or(uri);
    if base.contains('*') {
        return Err("Redirect URI may contain a wildcard only as a final /*");
    }
    if base.is_empty() || base.starts_with('/') {
        if uri.len() > 2048
            || has_dot_segment(base)
            || base.contains(['#', '\\'])
            || base.starts_with("//")
        {
            return Err("Relative redirect URI must be a plain path");
        }
        return Ok(());
    }
    validate_redirect_uri(base, allow_loopback_http)
}

/// Checks a client root URL: `${authBaseUrl}`, `${authAdminUrl}`, or an
/// HTTPS URL without credentials, query or fragment.
pub fn validate_root_url(url: &str, allow_loopback_http: bool) -> Result<(), &'static str> {
    if matches!(url, "${authBaseUrl}" | "${authAdminUrl}") {
        return Ok(());
    }
    validate_redirect_uri(url, allow_loopback_http)?;
    if url.contains('?') {
        return Err("Root URL must not have a query");
    }
    Ok(())
}

/// Resolves a registered redirect URI against the client's root URL;
/// `server` replaces `${authBaseUrl}` and `${authAdminUrl}`. A relative URI
/// without a root URL resolves to nothing.
pub fn resolve_redirect(registered: &str, root_url: Option<&str>, server: &str) -> Option<String> {
    if !registered.starts_with('/') {
        return Some(registered.to_owned());
    }
    let root = match root_url? {
        "${authBaseUrl}" | "${authAdminUrl}" => server,
        root => root,
    };
    Some(format!("{}{registered}", root.trim_end_matches('/')))
}

/// Reports whether a requested redirect URI matches a resolved registered
/// one. A registered `X/*` matches `X` and anything below `X/`, with any
/// query, unless the request has user info or dot segments; anything else
/// matches only exactly. A request with a fragment never matches.
pub fn redirect_matches(registered: &str, requested: &str) -> bool {
    if requested.contains('#') {
        return false;
    }
    let Some(prefix) = registered.strip_suffix("/*") else {
        return requested == registered;
    };
    let Ok(parsed) = Url::parse(requested) else {
        return false;
    };
    let path = requested
        .split_once('?')
        .map_or(requested, |(path, _)| path);
    parsed.username().is_empty()
        && parsed.password().is_none()
        && !has_dot_segment(path)
        && (path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/')))
}

/// Whether a path has a `.` or `..` segment, which URL parsing would
/// collapse and so move a request outside a matched prefix.
fn has_dot_segment(path: &str) -> bool {
    path.split('/').any(|segment| {
        matches!(segment, "." | "..")
            || segment.eq_ignore_ascii_case("%2e")
            || segment.eq_ignore_ascii_case("%2e%2e")
            || segment.eq_ignore_ascii_case(".%2e")
            || segment.eq_ignore_ascii_case("%2e.")
    })
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
    use super::{
        redirect_matches, resolve_redirect, validate_redirect_pattern, validate_redirect_uri,
        validate_root_url, validate_web_origin,
    };

    const SERVER: &str = "https://login.example";

    /// The recorded `rooted-app` and `account-console` cases.
    #[test]
    fn redirect_matching_follows_the_reference() {
        let account =
            resolve_redirect("/realms/r/account/*", Some("${authBaseUrl}"), SERVER).unwrap();
        let relative =
            resolve_redirect("/cb", Some("https://app.example.invalid"), SERVER).unwrap();
        let wildcard = "https://exact.example.invalid/*";
        let query = "https://query.example.invalid/cb?x=1";
        let matching = |requested: &str| {
            [account.as_str(), relative.as_str(), wildcard, query]
                .iter()
                .any(|registered| redirect_matches(registered, requested))
        };
        for accepted in [
            "https://login.example/realms/r/account/",
            "https://login.example/realms/r/account/x/y?z=1",
            "https://login.example/realms/r/account",
            "https://app.example.invalid/cb",
            "https://exact.example.invalid/any/path",
            "https://exact.example.invalid/",
            "https://exact.example.invalid",
            "https://exact.example.invalid/p?q=1",
            "https://query.example.invalid/cb?x=1",
        ] {
            assert!(matching(accepted), "{accepted}");
        }
        for refused in [
            "https://login.example/realms/r/other",
            "http://evil.example.invalid/realms/r/account/",
            "https://login.example/realms/r/account/../other",
            "https://login.example/realms/r/account/%2e%2e/other",
            "https://login.example/cb",
            "https://user@exact.example.invalid/p",
            "https://exact.example.invalid:8443/p",
            "https://exact.example.invalidx/p",
            "https://query.example.invalid/cb?x=2",
            "https://query.example.invalid/cb",
            "https://app.example.invalid/cb#f",
            "https://APP.example.invalid/cb",
        ] {
            assert!(!matching(refused), "{refused}");
        }
    }

    #[test]
    fn relative_redirects_need_a_root_url() {
        assert_eq!(resolve_redirect("/cb", None, SERVER), None);
        assert_eq!(
            resolve_redirect("https://app.example/cb", None, SERVER).as_deref(),
            Some("https://app.example/cb")
        );
        assert_eq!(
            resolve_redirect("/cb", Some("https://app.example/"), SERVER).as_deref(),
            Some("https://app.example/cb")
        );
    }

    #[test]
    fn redirect_patterns_allow_only_a_final_wildcard() {
        assert!(validate_redirect_pattern("https://app.example/*", false).is_ok());
        assert!(validate_redirect_pattern("/realms/r/account/*", false).is_ok());
        assert!(validate_redirect_pattern("/cb", false).is_ok());
        for bad in [
            "*",
            "https://*.example/cb",
            "https://app.example/*/x",
            "/a/../b",
            "//evil.example/cb",
            "http://app.example/*",
        ] {
            assert!(validate_redirect_pattern(bad, false).is_err(), "{bad}");
        }
        assert!(validate_root_url("${authBaseUrl}", false).is_ok());
        assert!(validate_root_url("https://app.example", false).is_ok());
        assert!(validate_root_url("https://app.example?x=1", false).is_err());
    }

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
