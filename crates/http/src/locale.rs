//! The locale of a request, as Keycloak's default locale selector picks it:
//! the locale picked with `kc_locale`, the user's own locale, the client's
//! `ui_locales`, the `KEYCLOAK_LOCALE` cookie, then `Accept-Language`, each
//! matched against the realm's supported locales, then the realm's default
//! locale, then English.
//!
//! Follows `DefaultLocaleSelectorProvider`, `LocaleBean` and
//! `DefaultLocaleUpdaterProvider` at the pinned revision, and
//! `tests/reference/account-settings-observations.json` and
//! `tests/reference/login-settings-observations.json`.

use std::collections::HashMap;
use std::sync::LazyLock;

use axum::http::{HeaderMap, header};
use rs_keycloak_storage_postgres::{LoginLocale, UserSettings};

use crate::login_theme::Messages;

/// The name of the cookie that remembers a chosen locale.
pub(crate) const COOKIE: &str = "KEYCLOAK_LOCALE";

/// For each theme locale, the label of every theme locale as the pinned
/// themes generate it on a page in that locale: the JDK's name in the
/// page's language, then its own name in parentheses unless it is the
/// page's locale. The login and account themes list the same locales.
static NAMES: LazyLock<HashMap<String, HashMap<String, String>>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("account_console/locale_names.json")).unwrap_or_default()
});

/// Each theme locale's display name in its own language.
static OWN_NAMES: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    NAMES
        .iter()
        .filter_map(|(tag, names)| names.get(tag).map(|name| (tag.clone(), name.clone())))
        .collect()
});

/// The locale choices a request carries besides its headers.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Choices<'a> {
    /// The locale picked with `kc_locale` during this login.
    pub(crate) picked: Option<&'a str>,
    /// The user's stored locale.
    pub(crate) user: Option<&'a str>,
    /// The client's space-separated `ui_locales`.
    pub(crate) client: Option<&'a str>,
}

/// What a login page shows of its realm and locale: the `lang` and `dir`
/// of its `html` element, its messages, the realm's name and its language
/// choice.
#[derive(Clone, Debug)]
pub(crate) struct PageLocale {
    /// The page's language tag.
    pub(crate) lang: String,
    /// `rtl` or `ltr`; absent unless the realm is internationalized, as the
    /// reference's login template writes it.
    pub(crate) dir: Option<&'static str>,
    /// The page's messages.
    pub(crate) messages: Messages,
    /// The realm's display name, else its name; empty outside a realm.
    pub(crate) realm_label: String,
    /// Whether the realm's username is the email, which names the
    /// username field.
    pub(crate) email_as_username: bool,
    /// The realm's locales and their labels, in display order; empty unless
    /// the realm is internationalized with more than one locale.
    pub(crate) languages: Vec<(String, String)>,
}

impl PageLocale {
    /// English without a direction, for pages outside a realm's login.
    pub(crate) fn english() -> Self {
        Self {
            lang: "en".to_owned(),
            dir: None,
            messages: Messages::english(),
            realm_label: String::new(),
            email_as_username: false,
            languages: Vec::new(),
        }
    }

    /// The locale of a login or required-action page.
    pub(crate) fn login(state: &LoginLocale, headers: &HeaderMap) -> Self {
        let choices = Choices {
            picked: state.requested.as_deref(),
            user: state.user.as_deref(),
            client: state.client.as_deref(),
        };
        let settings = &state.settings;
        let lang = resolve(settings, choices, headers);
        let messages = Messages::new(&lang, settings, &state.texts);
        // `LocaleBean` checks the direction of the locale's label.
        let dir = settings.internationalization_enabled.then(|| {
            if is_right_to_left(&messages.language_label(&lang)) {
                "rtl"
            } else {
                "ltr"
            }
        });
        let languages =
            if settings.internationalization_enabled && settings.supported_locales.len() > 1 {
                messages.languages(&settings.supported_locales)
            } else {
                Vec::new()
            };
        Self {
            lang,
            dir,
            messages,
            realm_label: state.realm_label.clone(),
            email_as_username: settings.registration_email_as_username,
            languages,
        }
    }

    /// The message key that labels the username field, as the reference's
    /// login template picks it with email login allowed.
    pub(crate) fn username_key(&self) -> &'static str {
        if self.email_as_username {
            "email"
        } else {
            "usernameOrEmail"
        }
    }

    /// The `html` element's attributes, starting with a space.
    pub(crate) fn attributes(&self) -> String {
        match self.dir {
            Some(dir) => format!(" lang=\"{}\" dir=\"{dir}\"", self.lang),
            None => format!(" lang=\"{}\"", self.lang),
        }
    }
}

/// The `KEYCLOAK_LOCALE` cookie for a realm, as the reference sets it.
pub(crate) fn cookie(path_prefix: &str, realm: &str, locale: &str) -> String {
    format!(
        "{COOKIE}={locale};Version=1;Path={path_prefix}/realms/{realm}/;Secure;HttpOnly;SameSite=None"
    )
}

/// The header that removes the `KEYCLOAK_LOCALE` cookie, as the reference
/// sends it.
pub(crate) fn expired_cookie(path_prefix: &str, realm: &str) -> String {
    format!("{COOKIE}=;Version=1;Path={path_prefix}/realms/{realm}/;Max-Age=0")
}

/// Whether a `kc_locale` value can be kept and sent back in a cookie:
/// letters, digits, `-` and `_`, up to 255 bytes.
pub(crate) fn acceptable_pick(locale: &str) -> bool {
    !locale.is_empty()
        && locale.len() <= 255
        && locale
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// The parts of a language tag that matching compares, as Java's
/// `Locale.forLanguageTag` reads them.
#[derive(Debug, PartialEq, Eq)]
struct Tag {
    /// Lowercase language, empty when the tag is not well formed.
    language: String,
    /// Titlecase script, if any.
    script: String,
    /// Uppercase region, if any.
    region: String,
}

impl Tag {
    /// Reads a tag; parsing stops at the first subtag out of place, and a
    /// tag that does not start with a language has none.
    fn parse(text: &str) -> Self {
        let mut tag = Self {
            language: String::new(),
            script: String::new(),
            region: String::new(),
        };
        let mut subtags = text.split('-').peekable();
        match subtags.next() {
            Some(language)
                if (2..=8).contains(&language.len())
                    && language.bytes().all(|byte| byte.is_ascii_alphabetic()) =>
            {
                tag.language = language.to_ascii_lowercase();
            }
            _ => return tag,
        }
        if let Some(script) = subtags.next_if(|subtag| {
            subtag.len() == 4 && subtag.bytes().all(|byte| byte.is_ascii_alphabetic())
        }) {
            let lower = script.to_ascii_lowercase();
            tag.script = lower[..1].to_ascii_uppercase() + &lower[1..];
        }
        if let Some(region) = subtags.next_if(|subtag| {
            (subtag.len() == 2 && subtag.bytes().all(|byte| byte.is_ascii_alphabetic()))
                || (subtag.len() == 3 && subtag.bytes().all(|byte| byte.is_ascii_digit()))
        }) {
            tag.region = region.to_ascii_uppercase();
        }
        tag
    }

    /// The tag in canonical case; `und` without a language.
    fn canonical(&self) -> String {
        let mut text = if self.language.is_empty() {
            "und".to_owned()
        } else {
            self.language.clone()
        };
        for part in [&self.script, &self.region] {
            if !part.is_empty() {
                text.push('-');
                text.push_str(part);
            }
        }
        text
    }

    /// Keycloak's match: the same language, and the same region or a region
    /// on exactly one side.
    fn matches(&self, supported: &Self) -> bool {
        self.language == supported.language
            && (self.region.is_empty() != supported.region.is_empty()
                || self.region == supported.region)
    }
}

/// The supported locale that best matches a requested tag: the first match,
/// unless a later one has the requested region.
fn best_match(supported: &[String], requested: &str) -> Option<String> {
    let requested = Tag::parse(requested);
    let mut best: Option<Tag> = None;
    for candidate in supported.iter().map(|tag| Tag::parse(tag)) {
        if !requested.matches(&candidate) {
            continue;
        }
        let better = best.as_ref().is_none_or(|current| {
            candidate.region == requested.region && current.region != requested.region
        });
        if better {
            best = Some(candidate);
        }
    }
    best.map(|tag| tag.canonical())
}

/// `Accept-Language` entries by descending quality, keeping the order of
/// equal ones; entries with quality zero are left out.
fn accepted_languages(headers: &HeaderMap) -> Vec<String> {
    let mut entries: Vec<(u16, String)> = headers
        .get_all(header::ACCEPT_LANGUAGE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|entry| {
            let mut parts = entry.split(';').map(str::trim);
            let tag = parts.next().filter(|tag| !tag.is_empty())?;
            let quality = parts
                .find_map(|parameter| parameter.strip_prefix("q="))
                .map_or(Some(1000), |quality| {
                    quality
                        .parse::<f32>()
                        .ok()
                        .filter(|quality| (0.0..=1.0).contains(quality))
                        .map(|quality| (quality * 1000.0).round() as u16)
                })?;
            (quality > 0).then(|| (quality, tag.to_owned()))
        })
        .collect();
    entries.sort_by_key(|(quality, _)| std::cmp::Reverse(*quality));
    entries.into_iter().map(|(_, tag)| tag).collect()
}

/// The locale a page is shown in, as a language tag.
pub(crate) fn resolve(
    settings: &UserSettings,
    choices: Choices<'_>,
    headers: &HeaderMap,
) -> String {
    if !settings.internationalization_enabled {
        return "en".to_owned();
    }
    let supported = &settings.supported_locales;
    let cookie = crate::oidc::cookie(headers, COOKIE);
    // `ui_locales` counts by its first tag that matches.
    let client = choices
        .client
        .and_then(|tags| tags.split(' ').find_map(|tag| best_match(supported, tag)));
    choices
        .picked
        .into_iter()
        .chain(choices.user)
        .map(|tag| best_match(supported, tag))
        .chain([client])
        .flatten()
        .chain(
            cookie
                .map(str::to_owned)
                .into_iter()
                .chain(accepted_languages(headers))
                .filter_map(|requested| best_match(supported, &requested)),
        )
        .next()
        .or_else(|| {
            settings
                .default_locale
                .as_deref()
                .map(|tag| Tag::parse(tag).canonical())
        })
        .unwrap_or_else(|| "en".to_owned())
}

/// The locale whose messages fill in what a locale's bundles lack, as
/// `LocaleUtil.getParentLocale`: a tag with a region falls back to its
/// language, a language to the realm's default locale (English when the
/// default has the same language or is unset), and English to nothing.
pub(crate) fn parent(tag: &str, settings: &UserSettings) -> Option<String> {
    if tag == "en" {
        return None;
    }
    let parsed = Tag::parse(tag);
    if !parsed.region.is_empty() {
        return Some(Tag::parse(&parsed.language).canonical());
    }
    let default = settings
        .default_locale
        .as_deref()
        .filter(|_| settings.internationalization_enabled)
        .map(Tag::parse);
    Some(match default {
        Some(default) if default.language != parsed.language => default.canonical(),
        _ => "en".to_owned(),
    })
}

/// The bundle names that hold a locale's own messages, later ones winning:
/// the JDK's `ResourceBundle` name, then for Chinese with a region the
/// script bundle the pinned theme maps it to.
pub(crate) fn bundle_names(tag: &str) -> Vec<String> {
    let parsed = Tag::parse(tag);
    if parsed.language.is_empty() {
        return Vec::new();
    }
    let name = [&parsed.language, &parsed.script, &parsed.region]
        .into_iter()
        .filter(|part| !part.is_empty())
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("_");
    let mut names = vec![name];
    let script = match (parsed.language.as_str(), parsed.region.as_str()) {
        ("zh", "TW") => Some("zh_Hant"),
        ("zh", "CN") => Some("zh_Hans"),
        _ => None,
    };
    names.extend(script.map(str::to_owned));
    names
}

/// The label a page in locale `page` generates for the theme locale
/// `listed`, as `DefaultThemeManager.addlocaleTranslations`; `None` when
/// the locale is not the theme's or no name table covers the page's
/// language. A page locale outside the theme uses its language's names.
pub(crate) fn generated_label(page: &str, listed: &str) -> Option<String> {
    if let Some(names) = NAMES.get(page) {
        return names.get(listed).cloned();
    }
    let language = Tag::parse(page).language;
    let name = NAMES.get(&language)?.get(listed)?;
    // The language's own table names it without the suffix.
    if listed == language {
        Some(format!("{name} ({})", OWN_NAMES.get(listed)?))
    } else {
        Some(name.clone())
    }
}

/// Whether a locale's display name is written right to left, as Java's
/// `Bidi` decides: any strong right-to-left character makes it so.
pub(crate) fn is_right_to_left(label: &str) -> bool {
    label.chars().any(|character| {
        matches!(u32::from(character),
            0x0590..=0x08FF | 0xFB1D..=0xFDFF | 0xFE70..=0xFEFF | 0x10800..=0x10FFF | 0x1E800..=0x1EFFF)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn settings(supported: &[&str], default: Option<&str>) -> UserSettings {
        UserSettings {
            internationalization_enabled: true,
            supported_locales: supported.iter().map(|tag| (*tag).to_owned()).collect(),
            default_locale: default.map(str::to_owned),
            ..UserSettings::default()
        }
    }

    fn accepting(value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static(value));
        headers
    }

    #[test]
    fn tags_are_read_like_java_locales() {
        assert_eq!(Tag::parse("PT-br").canonical(), "pt-BR");
        assert_eq!(Tag::parse("zh-hans-cn").canonical(), "zh-Hans-CN");
        assert_eq!(Tag::parse("en_US").canonical(), "und");
        assert_eq!(Tag::parse("").canonical(), "und");
    }

    #[test]
    fn a_region_on_one_side_still_matches() {
        let supported = ["de".to_owned(), "pt-BR".to_owned(), "zh-CN".to_owned()];
        assert_eq!(best_match(&supported, "de-DE").as_deref(), Some("de"));
        assert_eq!(best_match(&supported, "pt").as_deref(), Some("pt-BR"));
        assert_eq!(best_match(&supported, "pt-PT"), None);
        assert_eq!(best_match(&supported, "zh-TW"), None);
    }

    #[test]
    fn the_requested_region_wins_over_the_first_match() {
        let supported = ["de-AT".to_owned(), "de-CH".to_owned()];
        assert_eq!(best_match(&supported, "de-CH").as_deref(), Some("de-CH"));
        assert_eq!(best_match(&supported, "de").as_deref(), Some("de-AT"));
    }

    #[test]
    fn higher_quality_comes_first() {
        let realm = settings(&["fr", "ja"], Some("de"));
        let none = Choices::default();
        assert_eq!(
            resolve(&realm, none, &accepting("fr;q=0.2, ja;q=0.8")),
            "ja"
        );
        assert_eq!(resolve(&realm, none, &accepting("ja;q=0, fr;q=0.1")), "fr");
        assert_eq!(resolve(&realm, none, &accepting("*")), "de");
    }

    fn user(locale: &str) -> Choices<'_> {
        Choices {
            user: Some(locale),
            ..Choices::default()
        }
    }

    #[test]
    fn the_user_locale_comes_before_the_cookie_and_header() {
        let realm = settings(&["ar", "fr", "ja"], None);
        let mut headers = accepting("ja");
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("KEYCLOAK_LOCALE=fr"),
        );
        assert_eq!(resolve(&realm, user("ar"), &headers), "ar");
        assert_eq!(resolve(&realm, user("it"), &headers), "fr");
        assert_eq!(resolve(&realm, Choices::default(), &accepting("it")), "en");
    }

    #[test]
    fn the_pick_comes_first_and_ui_locales_after_the_user() {
        let realm = settings(&["ar", "fr", "ja"], None);
        let mut headers = accepting("fr");
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("KEYCLOAK_LOCALE=fr"),
        );
        let choices = |picked, user, client| Choices {
            picked,
            user,
            client,
        };
        let all = choices(Some("ar"), Some("ja"), Some("fr"));
        assert_eq!(resolve(&realm, all, &headers), "ar");
        let no_pick = choices(Some("it"), Some("ja"), Some("ar"));
        assert_eq!(resolve(&realm, no_pick, &headers), "ja");
        let client = choices(None, None, Some("it ja ar"));
        assert_eq!(resolve(&realm, client, &headers), "ja");
        let unsupported = choices(None, None, Some("it"));
        assert_eq!(resolve(&realm, unsupported, &headers), "fr");
    }

    #[test]
    fn disabled_internationalization_is_english() {
        let mut realm = settings(&["de"], Some("de"));
        realm.internationalization_enabled = false;
        assert_eq!(resolve(&realm, user("de"), &accepting("de")), "en");
    }

    #[test]
    fn login_pages_name_their_direction_only_when_internationalized() {
        let state = |enabled| LoginLocale {
            settings: UserSettings {
                internationalization_enabled: enabled,
                ..settings(&["ar", "he", "de"], None)
            },
            ..LoginLocale::default()
        };
        let page = |enabled, accepted| PageLocale::login(&state(enabled), &accepting(accepted));
        assert_eq!(page(true, "ar").attributes(), " lang=\"ar\" dir=\"rtl\"");
        // The theme does not name he, so its tag decides.
        assert_eq!(page(true, "he").attributes(), " lang=\"he\" dir=\"ltr\"");
        assert_eq!(page(false, "ar").attributes(), " lang=\"en\"");
    }

    #[test]
    fn parents_end_in_the_realm_default_then_english() {
        let realm = settings(&["de", "fr"], Some("fr"));
        let chain = |tag: &str| {
            let mut chain = vec![tag.to_owned()];
            while let Some(next) = parent(chain.last().map_or("", String::as_str), &realm) {
                chain.push(next);
            }
            chain
        };
        assert_eq!(chain("de-CH"), ["de-CH", "de", "fr", "en"]);
        assert_eq!(chain("fr"), ["fr", "en"]);
        assert_eq!(chain("zh-CN"), ["zh-CN", "zh", "fr", "en"]);
        let mut off = realm.clone();
        off.internationalization_enabled = false;
        assert_eq!(parent("de", &off).as_deref(), Some("en"));
    }

    #[test]
    fn chinese_regions_also_read_their_script_bundle() {
        assert_eq!(bundle_names("pt-BR"), ["pt_BR"]);
        assert_eq!(bundle_names("zh-CN"), ["zh_CN", "zh_Hans"]);
        assert_eq!(bundle_names("zh-Hant"), ["zh_Hant"]);
        assert!(bundle_names("").is_empty());
    }

    #[test]
    fn regional_pages_name_their_language_with_its_own_name() {
        assert_eq!(generated_label("de", "de").as_deref(), Some("Deutsch"));
        assert_eq!(
            generated_label("de-CH", "de").as_deref(),
            Some("Deutsch (Deutsch)")
        );
        assert_eq!(
            generated_label("de-CH", "fr").as_deref(),
            Some("Französisch (Français)")
        );
        assert_eq!(generated_label("de", "de-CH"), None);
        assert_eq!(generated_label("eo", "de"), None);
    }

    #[test]
    fn picks_are_kept_only_as_cookie_safe_tags() {
        assert!(acceptable_pick("pt-BR"));
        assert!(!acceptable_pick(""));
        assert!(!acceptable_pick("de;Path=/"));
        assert!(!acceptable_pick(&"a".repeat(256)));
    }

    #[test]
    fn right_to_left_follows_the_display_name() {
        assert!(is_right_to_left("العربية"));
        assert!(is_right_to_left("فارسی"));
        assert!(!is_right_to_left("he"));
        assert!(!is_right_to_left("Deutsch"));
    }
}
