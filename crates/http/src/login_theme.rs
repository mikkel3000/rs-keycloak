//! The pinned login theme's message bundles and how a page reads them.
//!
//! The bundles in `login_theme/messages` come from the base login theme of
//! the pinned distribution, extracted by
//! `compatibility/extract_login_messages.py`. A page's messages follow
//! `DefaultThemeManager` and `LocaleUtil` at the pinned revision: the
//! page's locale first, then its parents down to the realm's default
//! locale and English, each locale reading its own bundles; values are
//! Java `MessageFormat` patterns. Checked by
//! `tests/reference/login-message-observations.json`.

use std::collections::HashMap;
use std::sync::LazyLock;

use icu_normalizer::DecomposingNormalizerBorrowed;
use icu_properties::CodePointMapData;
use icu_properties::props::GeneralCategory;
use rs_keycloak_storage_postgres::UserSettings;

use crate::account_console::properties;
use crate::locale;

macro_rules! bundles {
    ($($name:literal),* $(,)?) => {
        [$(($name, include_str!(concat!("login_theme/messages/messages_", $name, ".properties")))),*]
    };
}

/// Each bundle's name, as in `messages_<name>.properties`, and its text.
const FILES: [(&str, &str); 41] = bundles!(
    "ar", "az", "ca", "cs", "da", "de", "el", "en", "es", "eu", "fa", "fi", "fr", "hr", "hu", "hy",
    "id", "it", "ja", "ka", "kk", "ko", "ky", "lt", "lv", "nl", "no", "pl", "pt", "pt_BR", "ro",
    "ru", "sk", "sl", "sv", "th", "tr", "uk", "vi", "zh_Hans", "zh_Hant",
);

type Bundle = HashMap<String, String>;

static BUNDLES: LazyLock<HashMap<&'static str, Bundle>> = LazyLock::new(|| {
    FILES
        .iter()
        .map(|(name, text)| (*name, properties::parse(text).into_iter().collect()))
        .collect()
});

/// Longest fallback chain followed; real chains have at most five locales.
const MAX_LEVELS: usize = 8;

/// One locale of a page's fallback chain and its bundles, later ones
/// winning.
#[derive(Clone, Debug)]
struct Level {
    tag: String,
    bundles: Vec<&'static Bundle>,
}

/// The messages of a page in one locale.
#[derive(Clone, Debug)]
pub(crate) struct Messages {
    /// Most specific locale first.
    levels: Vec<Level>,
}

impl Messages {
    /// The messages of a page in `lang` in a realm with these settings.
    pub(crate) fn new(lang: &str, settings: &UserSettings) -> Self {
        let mut levels: Vec<Level> = Vec::new();
        let mut next = Some(lang.to_owned());
        while let Some(tag) = next.take() {
            if levels.len() == MAX_LEVELS || levels.iter().any(|level| level.tag == tag) {
                break;
            }
            next = locale::parent(&tag, settings);
            let bundles = locale::bundle_names(&tag)
                .iter()
                .filter_map(|name| BUNDLES.get(name.as_str()))
                .collect();
            levels.push(Level { tag, bundles });
        }
        Self { levels }
    }

    /// English messages, for pages outside a realm's login.
    pub(crate) fn english() -> Self {
        Self::new("en", &UserSettings::default())
    }

    /// The most specific value of a key, if any bundle has it.
    fn value(&self, key: &str) -> Option<&'static str> {
        self.levels.iter().find_map(|level| {
            level
                .bundles
                .iter()
                .rev()
                .find_map(|bundle| bundle.get(key).map(String::as_str))
        })
    }

    /// A message with its arguments; a missing key stands for itself, as
    /// the reference's `msg` does.
    pub(crate) fn text(&self, key: &str, args: &[&str]) -> String {
        format(self.value(key).unwrap_or(key), args)
    }

    /// A message with its arguments, escaped for HTML.
    pub(crate) fn html(&self, key: &str, args: &[&str]) -> String {
        escape(&self.text(key, args))
    }

    /// How a page in these messages names a locale in its language choice:
    /// the most specific bundle's or generated `locale_` label, else the
    /// tag itself, as `LocaleBean` reads it.
    pub(crate) fn language_label(&self, listed: &str) -> String {
        let key = format!("locale_{listed}");
        self.levels
            .iter()
            .find_map(|level| {
                level
                    .bundles
                    .iter()
                    .rev()
                    .find_map(|bundle| bundle.get(&key).cloned())
                    .or_else(|| locale::generated_label(&level.tag, listed))
            })
            .unwrap_or_else(|| listed.to_owned())
    }

    /// A realm's locales with their labels, in the order the reference's
    /// collator gives at primary strength.
    pub(crate) fn languages(&self, supported: &[String]) -> Vec<(String, String)> {
        let mut languages: Vec<(String, String)> = supported
            .iter()
            .map(|tag| (tag.clone(), self.language_label(tag)))
            .collect();
        languages.sort_by_cached_key(|(_, label)| sort_key(label));
        languages
    }
}

/// Formats a Java `MessageFormat` pattern: `''` is a quote, text between
/// single quotes is literal, and `{n}` or `{n,...}` is argument `n`; an
/// argument that was not given stays `{n}`, as in Java.
pub(crate) fn format(pattern: &str, args: &[&str]) -> String {
    let mut formatted = String::with_capacity(pattern.len());
    let mut characters = pattern.chars().peekable();
    let mut quoted = false;
    while let Some(character) = characters.next() {
        match character {
            '\'' if characters.next_if_eq(&'\'').is_some() => formatted.push('\''),
            '\'' => quoted = !quoted,
            '{' if !quoted => {
                let element: String = characters
                    .by_ref()
                    .take_while(|&next| next != '}')
                    .collect();
                let index = element.split(',').next().map(str::trim);
                match index.and_then(|index| index.parse::<usize>().ok()) {
                    Some(position) if position < args.len() => formatted.push_str(args[position]),
                    _ => {
                        formatted.push('{');
                        formatted.push_str(index.unwrap_or_default());
                        formatted.push('}');
                    }
                }
            }
            other => formatted.push(other),
        }
    }
    formatted
}

/// Escapes text for HTML content and attribute values.
pub(crate) fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// A key that orders labels as a primary-strength collator does for the
/// recorded locales: accents and case ignored, then code point order.
/// The JDK's collator is not reproduced for scripts it orders otherwise.
fn sort_key(label: &str) -> String {
    let marks = CodePointMapData::<GeneralCategory>::new();
    DecomposingNormalizerBorrowed::new_nfd()
        .normalize(label)
        .chars()
        .filter(|&character| marks.get(character) != GeneralCategory::NonspacingMark)
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm(supported: &[&str], default: Option<&str>) -> UserSettings {
        UserSettings {
            internationalization_enabled: true,
            supported_locales: supported.iter().map(|tag| (*tag).to_owned()).collect(),
            default_locale: default.map(str::to_owned),
            ..UserSettings::default()
        }
    }

    #[test]
    fn every_bundle_is_embedded() {
        let directory =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/login_theme/messages");
        let mut files: Vec<String> = std::fs::read_dir(directory)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        files.sort();
        let embedded: Vec<String> = FILES
            .iter()
            .map(|(name, _)| format!("messages_{name}.properties"))
            .collect();
        assert_eq!(files, embedded);
    }

    #[test]
    fn quotes_and_arguments_follow_message_format() {
        assert_eq!(format("Nom d''utilisateur", &[]), "Nom d'utilisateur");
        assert_eq!(format("Sign in to {0}", &["Realm"]), "Sign in to Realm");
        assert_eq!(format("'{0}' and {1}", &["a"]), "{0} and {1}");
        assert_eq!(format("{0,number} left", &["3"]), "3 left");
    }

    #[test]
    fn missing_keys_fall_back_through_the_realm_default() {
        let settings = realm(&["de-CH", "lv", "fr"], Some("fr"));
        let swiss = Messages::new("de-CH", &settings);
        assert_eq!(swiss.text("doLogIn", &[]), "Anmelden");
        let latvian = Messages::new("lv", &settings);
        assert_eq!(
            latvian.text("verifyEmailMessage", &[]),
            "Vous devez vérifier votre adresse de courriel pour activer votre compte."
        );
        assert_eq!(latvian.text("noSuchKey", &[]), "noSuchKey");
        let chinese = Messages::new("zh-CN", &settings);
        assert_eq!(chinese.text("doLogIn", &[]), "登录");
    }

    #[test]
    fn labels_sort_without_accents_or_case() {
        let settings = realm(&["en", "de", "de-CH", "zh-CN", "ar"], None);
        let tags: Vec<String> = Messages::new("de", &settings)
            .languages(&settings.supported_locales)
            .into_iter()
            .map(|(tag, _)| tag)
            .collect();
        assert_eq!(tags, ["ar", "zh-CN", "de-CH", "de", "en"]);
        assert_eq!(sort_key("Ķīniešu"), "kiniesu");
    }
}
