//! The pinned Keycloak account console, served from the directory that
//! `compatibility/extract_account_console.py` fills and
//! `RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR` names: the console page and its
//! sub-paths, theme resources under `/resources/{version}/` and message
//! bundles under `/resources/{realm}/account/{locale}`.
//!
//! Follows `tests/reference/account-console-observations.json`. Without the
//! setting, every route here answers 404 and account routes stay JSON only.

mod properties;

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::path::{Path as FilePath, PathBuf};
use std::sync::OnceLock;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{OriginalUri, Path, Query, RawPathParams, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rs_keycloak_protocols::client_urls::{redirect_matches, resolve_redirect};
use rs_keycloak_storage_postgres::StorageError;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::locale;
use crate::oidc::{OidcState, digest};
use crate::security_headers::{self, Framing};

/// The page template: Keycloak's keycloak.v3 `index.ftl` as rendered by the
/// reference, with `{{name}}` where values vary. `{{entry}}` takes the build
/// entry's lines first, as they hold `{{resourceUrl}}` themselves.
const PAGE: &str = include_str!("account_console/index.html");

/// Display names of each listed locale, by the locale of the bundle they are
/// in. The reference generates them from its JDK's locale data; these are
/// its recorded values.
const LOCALE_NAMES: &str = include_str!("account_console/locale_names.json");

/// Account client roles the `account-console` client's scope can carry.
/// Feature checks only see these, as in the reference.
const CONSOLE_SCOPE_ROLES: [&str; 3] = ["manage-account", "manage-account-links", "view-groups"];

/// The resource version in theme URLs: five characters of `[0-9a-z]`, the
/// format the reference accepts, derived from this server's version so it
/// changes when the server does.
pub(crate) fn resource_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        let hash = Sha256::digest(concat!("rs-keycloak ", env!("CARGO_PKG_VERSION")).as_bytes());
        hash.iter()
            .take(5)
            .map(|byte| char::from(b"0123456789abcdefghijklmnopqrstuvwxyz"[usize::from(byte % 36)]))
            .collect()
    })
}

/// Why the console directory could not be used.
#[derive(Debug)]
pub struct LoadError(&'static str);

impl fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for LoadError {}

/// The extracted console: resource directories, the build entry and every
/// locale's message bundle, read once at startup.
pub struct AccountConsole {
    resources: PathBuf,
    common: PathBuf,
    entry_lines: String,
    locales: Vec<String>,
    bundles: HashMap<String, Bundle>,
}

/// One locale's messages, sorted by key, and their JSON list.
struct Bundle {
    pairs: Vec<(String, String)>,
    json: Bytes,
}

#[derive(Serialize)]
struct Message<'a> {
    key: &'a str,
    value: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'static str>,
}

#[derive(Deserialize)]
struct ManifestChunk {
    file: String,
    #[serde(default, rename = "isEntry")]
    is_entry: bool,
    #[serde(default)]
    css: Vec<String>,
    #[serde(default)]
    imports: Vec<String>,
}

impl AccountConsole {
    /// Reads the directory: `account/` (the keycloak.v3 theme),
    /// `account-base/` (the base theme it extends) and `common/`.
    pub fn load(directory: &FilePath) -> Result<Self, LoadError> {
        let account = directory.join("account");
        let base = directory.join("account-base");
        let common = directory.join("common");
        let resources = account.join("resources");
        if !common.is_dir() || !resources.is_dir() {
            return Err(LoadError(
                "RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR must hold account/resources and common",
            ));
        }
        let manifest = std::fs::read(resources.join(".vite/manifest.json"))
            .map_err(|_| LoadError("Account console build manifest is missing"))?;
        let manifest: BTreeMap<String, ManifestChunk> = serde_json::from_slice(&manifest)
            .map_err(|_| LoadError("Account console build manifest is invalid"))?;
        let entry_lines = entry_lines(&manifest)?;
        let theme = theme_properties(&account)?;
        let base_theme = theme_properties(&base)?;
        let locales: Vec<String> = theme
            .get("locales")
            .or_else(|| base_theme.get("locales"))
            .ok_or(LoadError("Account console theme lists no locales"))?
            .split(',')
            .map(str::trim)
            .filter(|tag| !tag.is_empty())
            .map(str::to_owned)
            .collect();
        if !locales.iter().any(|tag| tag == "en") {
            return Err(LoadError("Account console theme must list en"));
        }
        let names: HashMap<String, HashMap<String, String>> = serde_json::from_str(LOCALE_NAMES)
            .map_err(|_| LoadError("Locale names are invalid"))?;
        let mut bundles = HashMap::new();
        for tag in &locales {
            let mut messages = BTreeMap::new();
            for file in bundle_files(tag) {
                for theme_directory in [&base, &account] {
                    let path = theme_directory.join(format!("messages/messages_{file}.properties"));
                    match std::fs::read_to_string(path) {
                        Ok(text) => messages.extend(properties::parse(&text)),
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(_) => return Err(LoadError("Account console messages are unreadable")),
                    }
                }
            }
            if let Some(names) = names.get(tag) {
                for listed in &locales {
                    if let Some(name) = names.get(listed) {
                        messages.insert(format!("locale_{listed}"), name.clone());
                    }
                }
            }
            let pairs: Vec<(String, String)> = messages.into_iter().collect();
            let json = message_list(&pairs, None);
            bundles.insert(tag.clone(), Bundle { pairs, json });
        }
        Ok(Self {
            resources,
            common,
            entry_lines,
            locales,
            bundles,
        })
    }

    /// The listed locale a request names: an exact tag, else the first
    /// listed tag of the same language, else `en`.
    fn bundle(&self, requested: &str) -> &Bundle {
        let requested = requested.replace('_', "-");
        let language = requested.split('-').next().unwrap_or_default();
        let tag = self
            .locales
            .iter()
            .find(|tag| tag.eq_ignore_ascii_case(&requested))
            .or_else(|| {
                self.locales.iter().find(|tag| {
                    tag.split('-')
                        .next()
                        .is_some_and(|own| own.eq_ignore_ascii_case(language))
                })
            })
            .map_or("en", String::as_str);
        &self.bundles[tag]
    }

    /// A locale's display name in its own bundle, if the theme has one.
    pub(crate) fn locale_label(&self, tag: &str) -> Option<&str> {
        let key = format!("locale_{tag}");
        let pairs = &self.bundle(tag).pairs;
        pairs
            .binary_search_by(|(name, _)| name.as_str().cmp(&key))
            .ok()
            .map(|index| pairs[index].1.as_str())
    }
}

/// The stylesheet, script and preload lines of the build entry, indented as
/// the reference template renders them.
fn entry_lines(manifest: &BTreeMap<String, ManifestChunk>) -> Result<String, LoadError> {
    let entry = manifest
        .values()
        .find(|chunk| chunk.is_entry)
        .ok_or(LoadError("Account console build manifest has no entry"))?;
    let mut lines = String::new();
    for style in &entry.css {
        lines.push_str(&format!(
            "        <link rel=\"stylesheet\" href=\"{{{{resourceUrl}}}}/{style}\">\n"
        ));
    }
    lines.push_str(&format!(
        "      <script type=\"module\" src=\"{{{{resourceUrl}}}}/{}\"></script>\n",
        entry.file
    ));
    for import in &entry.imports {
        let file = manifest
            .get(import)
            .map_or(import.as_str(), |chunk| &chunk.file);
        lines.push_str(&format!(
            "        <link rel=\"modulepreload\" href=\"{{{{resourceUrl}}}}/{file}\">\n"
        ));
    }
    Ok(lines)
}

fn theme_properties(theme: &FilePath) -> Result<HashMap<String, String>, LoadError> {
    let text = std::fs::read_to_string(theme.join("theme.properties"))
        .map_err(|_| LoadError("Account console theme.properties is missing"))?;
    Ok(properties::parse(&text).into_iter().collect())
}

/// Message files for a listed tag, most general first: English, the
/// language, then the full tag. Like Java's resource bundles, Chinese
/// regions map to their scripts.
fn bundle_files(tag: &str) -> Vec<String> {
    let language = tag.split('-').next().unwrap_or_default();
    let full = match tag {
        "zh-CN" => "zh_Hans".to_owned(),
        "zh-TW" => "zh_Hant".to_owned(),
        other => other.replace('-', "_"),
    };
    let mut files = vec!["en".to_owned()];
    for file in [language.to_owned(), full] {
        if !files.contains(&file) {
            files.push(file);
        }
    }
    files
}

fn message_list(pairs: &[(String, String)], source: Option<&'static str>) -> Bytes {
    let messages: Vec<Message<'_>> = pairs
        .iter()
        .map(|(key, value)| Message { key, value, source })
        .collect();
    Bytes::from(serde_json::to_vec(&messages).unwrap_or_default())
}

/// Console routes, mounted with the public routes below the issuer path.
pub(crate) fn routes() -> Router<OidcState> {
    Router::new()
        .route(
            "/resources/{first}/{kind}/{third}",
            get(messages).options(messages_preflight),
        )
        .route("/resources/{first}/{kind}/{third}/{*path}", get(resource))
        .route("/realms/{realm}/account/index.html", get(index_redirect))
        .route("/realms/{realm}/account/{*path}", get(sub_path))
}

/// Whether a request asks for the account API rather than the console: an
/// `application/json` Accept entry or content type.
pub(crate) fn wants_json(headers: &HeaderMap) -> bool {
    let is_json = |value: &str| {
        value
            .split(';')
            .next()
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
    };
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(is_json)
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(is_json)
}

/// Serves the console page for browser navigation to any account route
/// when the console is configured; JSON requests reach the account API.
pub(crate) async fn navigation(
    State(state): State<OidcState>,
    params: RawPathParams,
    request: Request,
    next: Next,
) -> Response {
    if state.account_console.is_some()
        && matches!(*request.method(), Method::GET | Method::HEAD)
        && !wants_json(request.headers())
        && let Some((_, realm)) = params.iter().find(|(name, _)| *name == "realm")
    {
        let realm = realm.to_owned();
        return page(&state, &realm, request.headers(), request.uri().query()).await;
    }
    next.run(request).await
}

async fn sub_path(
    State(state): State<OidcState>,
    Path((realm, _)): Path<(String, String)>,
    uri: OriginalUri,
    headers: HeaderMap,
) -> Response {
    if state.account_console.is_none() || wants_json(&headers) {
        return StatusCode::NOT_FOUND.into_response();
    }
    page(&state, &realm, &headers, uri.query()).await
}

/// The reference sends `index.html` one level up without normalizing.
async fn index_redirect(State(state): State<OidcState>, uri: OriginalUri) -> Response {
    if state.account_console.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let origin = issuer_origin(&state.issuer_base);
    let location = format!("{origin}{}/../", uri.path());
    let mut response = StatusCode::FOUND.into_response();
    match HeaderValue::from_str(&location) {
        Ok(value) => response.headers_mut().insert(header::LOCATION, value),
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    security_headers::apply(response.headers_mut(), Framing::Plain);
    response
}

/// The scheme and authority of the issuer, without its path.
pub(crate) fn issuer_origin(issuer_base: &str) -> String {
    url::Url::parse(issuer_base)
        .map_or_else(|_| String::new(), |url| url.origin().ascii_serialization())
}

/// The reference's answer for an unknown realm on browser routes.
pub(crate) fn realm_does_not_exist() -> Response {
    let mut response = (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "application/json")],
        json!({ "error": "Realm does not exist" }).to_string(),
    )
        .into_response();
    security_headers::apply(response.headers_mut(), Framing::Json);
    response
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CACHE_CONTROL, "no-store")],
        "Service unavailable",
    )
        .into_response()
}

/// What the signed-in visitor may see, all false for anonymous visitors,
/// and the locale they chose.
#[derive(Default)]
struct Features {
    applications: bool,
    groups: bool,
    delete_account: bool,
    locale: Option<String>,
}

async fn features(
    state: &OidcState,
    realm_id: &str,
    headers: &HeaderMap,
) -> Result<Features, StorageError> {
    let Some(token) = crate::oidc::cookie(headers, "KEYCLOAK_IDENTITY") else {
        return Ok(Features::default());
    };
    let Some(session) = state.storage.sso_session(realm_id, &digest(token)).await? else {
        return Ok(Features::default());
    };
    let roles = state
        .storage
        .effective_roles(realm_id, &session.user_id)
        .await?;
    let scoped: Vec<&str> = roles
        .clients
        .get("account")
        .into_iter()
        .flatten()
        .map(String::as_str)
        .filter(|role| CONSOLE_SCOPE_ROLES.contains(role))
        .collect();
    let manage = scoped.contains(&"manage-account");
    let groups = if manage || scoped.contains(&"view-groups") {
        state
            .storage
            .user_groups(realm_id, &session.user_id)
            .await?
            .is_some_and(|groups| !groups.is_empty())
    } else {
        false
    };
    let delete_action = state
        .storage
        .required_action_settings(realm_id)
        .await?
        .iter()
        .any(|setting| setting.alias == "delete_account" && setting.enabled);
    let locale = state
        .storage
        .user(realm_id, &session.user_id)
        .await?
        .and_then(|user| user.locale);
    Ok(Features {
        applications: manage,
        groups,
        delete_account: manage && delete_action,
        locale,
    })
}

/// The referring application: a `referrer` client and either its verified
/// `referrer_uri` or its home page.
async fn referrer(
    state: &OidcState,
    realm_id: &str,
    query: &HashMap<String, String>,
) -> Result<Option<(String, String)>, StorageError> {
    let Some(client_id) = query.get("referrer") else {
        return Ok(None);
    };
    let Some(client) = state
        .storage
        .clients(realm_id, Some(client_id))
        .await?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let server = state.issuer_base.trim_end_matches('/');
    let root = client.root_url.as_deref();
    let url = match query.get("referrer_uri") {
        Some(requested) => client
            .redirect_uris
            .iter()
            .any(|registered| {
                resolve_redirect(registered, root, server)
                    .is_some_and(|resolved| redirect_matches(&resolved, requested))
            })
            .then(|| requested.clone()),
        None => client
            .base_url
            .as_deref()
            .and_then(|base| resolve_redirect(base, root, server)),
    };
    // A blank name falls back to the identifier, as in the reference.
    let name = client
        .name
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(client.client_identifier);
    Ok(url.map(|url| (name, url)))
}

/// Renders the console page for a realm.
pub(crate) async fn page(
    state: &OidcState,
    realm: &str,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Response {
    let Some(console) = &state.account_console else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let realm_id = match state.storage.realm_id_by_name(realm).await {
        Ok(Some(realm_id)) => realm_id,
        Ok(None) => return realm_does_not_exist(),
        Err(_) => return unavailable(),
    };
    let query: HashMap<String, String> =
        url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    let (features, referrer, settings) = match tokio::try_join!(
        features(state, &realm_id, headers),
        referrer(state, &realm_id, &query),
        state.storage.user_settings(&realm_id)
    ) {
        Ok(found) => found,
        Err(_) => return unavailable(),
    };
    let server = state.issuer_base.trim_end_matches('/');
    let prefix = state.path_prefix();
    let resource_url = format!(
        "{prefix}/resources/{}/account/keycloak.v3",
        resource_version()
    );
    let common_url = format!("{prefix}/resources/{}/common/keycloak", resource_version());
    let (referrer_name, referrer_url) = referrer.unwrap_or_default();
    let locale = locale::resolve(&settings, features.locale.as_deref(), headers);
    let direction = if console
        .locale_label(&locale)
        .is_some_and(locale::is_right_to_left)
    {
        "rtl"
    } else {
        "ltr"
    };
    let flag = |enabled: bool| Cow::Borrowed(if enabled { "true" } else { "false" });
    let body = render(
        &render(PAGE, |name| match name {
            "entry" => Some(Cow::Borrowed(console.entry_lines.as_str())),
            _ => None,
        }),
        |name| {
            Some(match name {
                "locale" => json_text(&locale),
                "localeDir" => Cow::Borrowed(direction),
                "resourceUrl" => Cow::Borrowed(resource_url.as_str()),
                "resourceCommonUrl" => Cow::Borrowed(common_url.as_str()),
                "serverBaseUrl" => json_text(server),
                "authUrl" => json_text(&format!("{server}/")),
                "realm" => json_text(realm),
                "baseUrl" => json_text(&format!("{server}/realms/{realm}/account/")),
                "referrerName" => json_text(&referrer_name),
                "referrerUrl" => json_text(&referrer_url),
                "scope" => json_text(query.get("scope").map_or("", String::as_str)),
                "isRegistrationEmailAsUsername" => flag(settings.registration_email_as_username),
                "isEditUserNameAllowed" => flag(settings.edit_username_allowed),
                "isInternationalizationEnabled" => flag(settings.internationalization_enabled),
                "isLinkedAccountsEnabled" => flag(false),
                "deleteAccountAllowed" => flag(features.delete_account),
                "isViewApplicationsEnabled" => flag(features.applications),
                "isViewGroupsEnabled" => flag(features.groups),
                _ => return None,
            })
        },
    );
    let mut response = (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
            (header::CONTENT_LANGUAGE, "en"),
        ],
        body,
    )
        .into_response();
    security_headers::apply(response.headers_mut(), Framing::Page);
    response
}

/// Replaces each `{{name}}` in one pass, so values are never re-read.
fn render<'a>(template: &str, value: impl Fn(&str) -> Option<Cow<'a, str>>) -> String {
    let mut output = String::with_capacity(template.len() + 512);
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        output.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => match value(&after[..end]) {
                Some(replacement) => {
                    output.push_str(&replacement);
                    rest = &after[end + 2..];
                }
                None => {
                    output.push_str("{{");
                    rest = after;
                }
            },
            None => {
                output.push_str(rest);
                rest = "";
            }
        }
    }
    output.push_str(rest);
    output
}

/// A string escaped for a JSON string inside a `<script>` element.
fn json_text(value: &str) -> Cow<'static, str> {
    let quoted = serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned());
    Cow::Owned(
        quoted[1..quoted.len() - 1]
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026"),
    )
}

#[derive(Deserialize)]
struct MessagesQuery {
    source: Option<String>,
}

/// One locale's account messages as a key and value list.
async fn messages(
    State(state): State<OidcState>,
    Path((realm, kind, locale)): Path<(String, String, String)>,
    Query(query): Query<MessagesQuery>,
    headers: HeaderMap,
) -> Response {
    let mut response = match (&state.account_console, kind.as_str()) {
        (Some(console), "account") => match state.storage.realm_id_by_name(&realm).await {
            Ok(Some(_)) => {
                let bundle = console.bundle(&locale);
                let body = if query.source.as_deref() == Some("true") {
                    message_list(&bundle.pairs, Some("THEME"))
                } else {
                    bundle.json.clone()
                };
                let mut response = (
                    [(header::CONTENT_TYPE, "application/json;charset=UTF-8")],
                    body,
                )
                    .into_response();
                security_headers::apply(response.headers_mut(), Framing::Json);
                response
            }
            Ok(None) => not_found(),
            Err(_) => return unavailable(),
        },
        _ => not_found(),
    };
    allow_origin(&headers, &mut response);
    response
}

async fn messages_preflight(headers: HeaderMap) -> Response {
    let mut response = StatusCode::OK.into_response();
    if allow_origin(&headers, &mut response) {
        let added = response.headers_mut();
        added.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, HEAD, OPTIONS"),
        );
        added.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Origin, Accept, X-Requested-With, Access-Control-Request-Method, Access-Control-Request-Headers, DPoP, Content-Type, Authorization"));
        added.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("3600"),
        );
    }
    security_headers::apply(response.headers_mut(), Framing::Plain);
    response
}

/// Message bundles allow every origin, with credentials.
fn allow_origin(headers: &HeaderMap, response: &mut Response) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return false;
    };
    let added = response.headers_mut();
    added.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
    added.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    true
}

fn not_found() -> Response {
    let mut response = StatusCode::NOT_FOUND.into_response();
    security_headers::apply(response.headers_mut(), Framing::Plain);
    response
}

/// Whether a path is a plain relative path: no empty, dot or backslash
/// segments; a trailing slash names a directory.
fn plain_path(path: &str) -> bool {
    let path = path.strip_suffix('/').unwrap_or(path);
    !path.is_empty()
        && path
            .split('/')
            .all(|segment| !matches!(segment, "" | "." | "..") && !segment.contains(['\\', '\0']))
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("js" | "mjs") => "text/javascript",
        Some("css") => "text/css",
        Some("svg") => "image/svg+xml",
        Some("json") => "application/json",
        Some("html" | "htm") => "text/html",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}

/// A theme resource. Paths under the console's `assets/` carry a content
/// hash: they are served under any well-formed version with the current
/// version as ETag. Other paths under another version redirect to the
/// current one when the theme is named exactly.
async fn resource(
    State(state): State<OidcState>,
    Path((version, kind, theme, path)): Path<(String, String, String, String)>,
    uri: OriginalUri,
    headers: HeaderMap,
) -> Response {
    let Some(console) = &state.account_console else {
        return not_found();
    };
    let well_formed = version.len() == 5
        && version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase());
    if !well_formed || uri.path().contains('%') || !plain_path(&path) {
        return not_found();
    }
    let (directory, own_theme, hashed) = match kind.as_str() {
        // A directory answers empty and, in the reference, without an ETag.
        "account" => (
            &console.resources,
            "keycloak.v3",
            path.starts_with("assets/") && !path.ends_with('/'),
        ),
        "common" => (&console.common, "keycloak", false),
        _ => return not_found(),
    };
    let file = directory.join(&path);
    let current = resource_version();
    if version != current && !hashed && theme == own_theme {
        if tokio::fs::metadata(&file).await.is_err() {
            return not_found();
        }
        let location = format!(
            "{}/resources/{current}/{kind}/{theme}/{path}",
            state.issuer_base.trim_end_matches('/')
        );
        let mut response = StatusCode::TEMPORARY_REDIRECT.into_response();
        match HeaderValue::from_str(&location) {
            Ok(value) => response.headers_mut().insert(header::LOCATION, value),
            Err(_) => return not_found(),
        };
        security_headers::apply(response.headers_mut(), Framing::Plain);
        return response;
    }
    if hashed
        && headers
            .get(header::IF_NONE_MATCH)
            .is_some_and(|tag| tag.as_bytes() == current.as_bytes())
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        add_cache_headers(response.headers_mut(), hashed);
        security_headers::apply(response.headers_mut(), Framing::Plain);
        return response;
    }
    let body = match tokio::fs::metadata(&file).await {
        Ok(metadata) if metadata.is_dir() => Vec::new(),
        Ok(_) => match tokio::fs::read(&file).await {
            Ok(body) => body,
            Err(_) => return not_found(),
        },
        Err(_) => return not_found(),
    };
    let kind_of = if path.ends_with('/') {
        "application/octet-stream"
    } else {
        content_type(&path)
    };
    let mut response = ([(header::CONTENT_TYPE, kind_of)], body).into_response();
    add_cache_headers(response.headers_mut(), hashed);
    let framing = match kind_of {
        "application/json" => Framing::Json,
        "text/html" => Framing::Page,
        _ => Framing::Plain,
    };
    security_headers::apply(response.headers_mut(), framing);
    response
}

fn add_cache_headers(headers: &mut HeaderMap, hashed: bool) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if hashed && let Ok(tag) = HeaderValue::from_str(resource_version()) {
        headers.insert(header::ETAG, tag);
    }
}

#[cfg(test)]
mod tests {
    use super::{bundle_files, plain_path, render, resource_version};
    use std::borrow::Cow;

    #[test]
    fn resource_version_has_the_reference_format() {
        let version = resource_version();
        assert_eq!(version.len(), 5);
        assert!(
            version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase())
        );
    }

    #[test]
    fn bundle_files_go_from_general_to_specific() {
        assert_eq!(bundle_files("en"), ["en"]);
        assert_eq!(bundle_files("pt-BR"), ["en", "pt", "pt_BR"]);
        assert_eq!(bundle_files("zh-TW"), ["en", "zh", "zh_Hant"]);
    }

    #[test]
    fn plain_paths_reject_dot_segments() {
        assert!(plain_path("assets/main.js"));
        assert!(plain_path("assets/"));
        assert!(!plain_path("assets/../theme.properties"));
        assert!(!plain_path("./main.js"));
        assert!(!plain_path("a//b"));
    }

    #[test]
    fn render_does_not_reread_values() {
        let rendered = render("a {{x}} {{y}} {{z}}", |name| match name {
            "x" => Some(Cow::Borrowed("{{y}}")),
            "y" => Some(Cow::Borrowed("why")),
            _ => None,
        });
        assert_eq!(rendered, "a {{y}} why {{z}}");
    }
}
