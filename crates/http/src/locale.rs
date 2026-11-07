//! The locale of a request, as Keycloak's default locale selector picks it:
//! the user's own locale, the `KEYCLOAK_LOCALE` cookie, then
//! `Accept-Language`, each matched against the realm's supported locales,
//! then the realm's default locale, then English.
//!
//! Follows `DefaultLocaleSelectorProvider` at the pinned revision and
//! `tests/reference/account-settings-observations.json`.

use axum::http::{HeaderMap, header};
use rs_keycloak_storage_postgres::UserSettings;

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
    user_locale: Option<&str>,
    headers: &HeaderMap,
) -> String {
    if !settings.internationalization_enabled {
        return "en".to_owned();
    }
    let supported = &settings.supported_locales;
    let cookie = crate::oidc::cookie(headers, "KEYCLOAK_LOCALE");
    user_locale
        .into_iter()
        .chain(cookie)
        .map(str::to_owned)
        .chain(accepted_languages(headers))
        .find_map(|requested| best_match(supported, &requested))
        .or_else(|| {
            settings
                .default_locale
                .as_deref()
                .map(|tag| Tag::parse(tag).canonical())
        })
        .unwrap_or_else(|| "en".to_owned())
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
        assert_eq!(
            resolve(&realm, None, &accepting("fr;q=0.2, ja;q=0.8")),
            "ja"
        );
        assert_eq!(resolve(&realm, None, &accepting("ja;q=0, fr;q=0.1")), "fr");
        assert_eq!(resolve(&realm, None, &accepting("*")), "de");
    }

    #[test]
    fn the_user_locale_comes_before_the_cookie_and_header() {
        let realm = settings(&["ar", "fr", "ja"], None);
        let mut headers = accepting("ja");
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("KEYCLOAK_LOCALE=fr"),
        );
        assert_eq!(resolve(&realm, Some("ar"), &headers), "ar");
        assert_eq!(resolve(&realm, Some("it"), &headers), "fr");
        assert_eq!(resolve(&realm, None, &accepting("it")), "en");
    }

    #[test]
    fn disabled_internationalization_is_english() {
        let mut realm = settings(&["de"], Some("de"));
        realm.internationalization_enabled = false;
        assert_eq!(resolve(&realm, Some("de"), &accepting("de")), "en");
    }

    #[test]
    fn right_to_left_follows_the_display_name() {
        assert!(is_right_to_left("العربية"));
        assert!(is_right_to_left("فارسی"));
        assert!(!is_right_to_left("he"));
        assert!(!is_right_to_left("Deutsch"));
    }
}
