//! Realm email shared by the admin API and login pages: SMTP settings from
//! the realm record, action links, and messages as the reference's
//! `FreeMarkerEmailTemplateProvider` makes them: in the user's locale, from
//! the email theme's bundles with the realm's localization texts over them.

use axum::http::HeaderMap;
use rs_keycloak_integrations::mail::{Mail, MailError, SmtpSettings, send};
use rs_keycloak_storage_postgres::{RealmRecord, StorageError};

use crate::locale::{self, Choices};
use crate::login_theme::{Messages, escape};
use crate::oidc::OidcState;

/// The realm's SMTP settings, if it has a server and a sender.
pub(crate) fn settings(realm: &RealmRecord) -> Option<SmtpSettings> {
    let smtp = realm.smtp.as_ref()?;
    Some(SmtpSettings {
        host: smtp.host.clone(),
        port: u16::try_from(smtp.port).ok()?,
        from: smtp.from.clone()?,
        from_display_name: smtp.from_display_name.clone(),
        starttls: smtp.starttls,
        ssl: smtp.ssl,
    })
}

/// The public action link for a key.
pub(crate) fn action_link(state: &OidcState, realm: &str, key: &str) -> String {
    format!(
        "{}/realms/{realm}/login-actions/action-token?key={key}",
        state.issuer_base.trim_end_matches('/')
    )
}

/// Which mail a link goes out in, with its theme keys.
pub(crate) enum Template<'a> {
    /// `password-reset.ftl`.
    PasswordReset,
    /// `email-verification.ftl`.
    EmailVerification,
    /// `executeActions.ftl` with the required actions it asks for.
    ExecuteActions(&'a [String]),
}

impl Template<'_> {
    fn keys(&self) -> (&'static str, &'static str) {
        match self {
            Self::PasswordReset => ("passwordResetSubject", "passwordReset"),
            Self::EmailVerification => ("emailVerificationSubject", "emailVerification"),
            Self::ExecuteActions(_) => ("executeActionsSubject", "executeActions"),
        }
    }
}

/// The user a mail goes to.
pub(crate) struct Recipient<'a> {
    /// The address.
    pub(crate) email: &'a str,
    /// The user's stored locale, if any.
    pub(crate) locale: Option<&'a str>,
}

/// The realm name mails show: the display name, else the name with its
/// first letter capitalized, as `getRealmName`.
fn realm_name(realm: &RealmRecord) -> String {
    realm.display_name.clone().unwrap_or_else(|| {
        let mut letters = realm.name.chars();
        letters.next().map_or_else(String::new, |first| {
            first.to_uppercase().chain(letters).collect()
        })
    })
}

/// The choice of a `{0,choice,...}` pattern for a count, as Java's
/// `ChoiceFormat`: the last limit the count reaches, `#` inclusive and
/// `<` exclusive.
fn choice(pattern: &str, count: i64) -> Option<String> {
    let body = pattern.trim().strip_prefix('{')?.strip_suffix('}')?;
    let mut parts = body.splitn(3, ',');
    let (_, kind, options) = (parts.next()?, parts.next()?.trim(), parts.next()?);
    if kind != "choice" {
        return None;
    }
    let mut chosen = None;
    for option in options.split('|') {
        let split = option.find(['#', '<'])?;
        let limit: f64 = option[..split].trim().parse().ok()?;
        let reached = if option[split..].starts_with('#') {
            count as f64 >= limit
        } else {
            count as f64 > limit
        };
        if reached || chosen.is_none() {
            chosen = Some(option[split + 1..].to_owned());
        }
    }
    chosen
}

/// A link lifetime in the mail's words, as `LinkExpirationFormatterMethod`:
/// the largest whole unit of days, hours, minutes or seconds.
fn expiration(messages: &Messages, minutes: i64) -> String {
    let mut value = minutes * 60;
    let mut unit = "seconds";
    if value > 0 && value % 60 == 0 {
        (unit, value) = ("minutes", value / 60);
        if value % 60 == 0 {
            (unit, value) = ("hours", value / 60);
            if value % 24 == 0 {
                (unit, value) = ("days", value / 24);
            }
        }
    }
    let key = format!("linkExpirationFormatter.timePeriodUnit.{unit}");
    let pattern = messages.value(&key).unwrap_or(&key);
    format!(
        "{value} {}",
        choice(pattern, value).unwrap_or_else(|| pattern.to_owned())
    )
}

const ALLOWED_TAGS: [&str; 8] = ["p", "br", "b", "strong", "i", "em", "u", "a"];

/// Keeps the markup an HTML mail may carry, as `kcSanitize` does with its
/// policy: paragraphs, breaks, emphasis and links to web or mail
/// addresses; other tags are dropped and their text kept.
fn sanitize(html: &str) -> String {
    let mut clean = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        clean.push_str(&rest[..start]);
        let Some(length) = rest[start..].find('>') else {
            clean.push_str("&lt;");
            rest = &rest[start + 1..];
            continue;
        };
        let tag = &rest[start + 1..start + length];
        rest = &rest[start + length + 1..];
        let closing = tag.starts_with('/');
        let name: String = tag
            .trim_start_matches('/')
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase();
        if !ALLOWED_TAGS.contains(&name.as_str()) {
            continue;
        }
        if closing {
            clean.push_str(&format!("</{name}>"));
        } else if name == "a" {
            let href = tag
                .split_once("href=\"")
                .and_then(|(_, value)| value.split_once('"'))
                .map(|(value, _)| value)
                .filter(|href| {
                    ["http://", "https://", "mailto:"]
                        .iter()
                        .any(|scheme| href.to_ascii_lowercase().starts_with(scheme))
                });
            match href {
                Some(href) => clean.push_str(&format!("<a href=\"{href}\">")),
                None => clean.push_str("<a>"),
            }
        } else {
            clean.push_str(&format!("<{name}>"));
        }
    }
    clean.push_str(rest);
    clean
}

/// Writes a mail in the recipient's locale. `headers` are the browser's
/// for mails a login sends, and empty for mails an admin asks for.
pub(crate) async fn compose(
    state: &OidcState,
    realm: &RealmRecord,
    recipient: &Recipient<'_>,
    headers: &HeaderMap,
    template: &Template<'_>,
    link: &str,
    lifespan: i32,
) -> Result<(String, String, String), StorageError> {
    let settings = &realm.user_settings;
    let choices = Choices {
        user: recipient.locale,
        ..Choices::default()
    };
    let lang = locale::resolve(settings, choices, headers);
    let texts = state.storage.localization_texts(&realm.id).await?;
    let messages = Messages::email(&lang, settings, &texts);
    let name = realm_name(realm);
    let minutes = (i64::from(lifespan) / 60).to_string();
    let formatted = expiration(&messages, i64::from(lifespan) / 60);
    let actions = match template {
        Template::ExecuteActions(actions) => Some(
            actions
                .iter()
                .map(|action| messages.text(&format!("requiredAction.{action}"), &[]))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        _ => None,
    };
    let args = |link: &str, name: &str, actions: Option<&str>, formatted: &str| -> Vec<String> {
        let mut args = vec![link.to_owned(), minutes.clone(), name.to_owned()];
        args.extend(actions.map(str::to_owned));
        args.push(formatted.to_owned());
        args
    };
    let (subject_key, body_key) = template.keys();
    let plain = args(link, &name, actions.as_deref(), &formatted);
    let plain: Vec<&str> = plain.iter().map(String::as_str).collect();
    let marked = args(
        &escape(link),
        &escape(&name),
        actions.as_deref().map(escape).as_deref(),
        &escape(&formatted),
    );
    let marked: Vec<&str> = marked.iter().map(String::as_str).collect();
    // The subject is formatted without arguments, as the reference passes
    // none for these mails, so a `{0}` in it stays.
    let subject = messages.text(subject_key, &[]);
    let text = messages.text(&format!("{body_key}Body"), &plain);
    let direction = if locale::is_right_to_left(&messages.language_label(&lang)) {
        "rtl"
    } else {
        "ltr"
    };
    let html = format!(
        "<html lang=\"{}\" dir=\"{direction}\"><body>{}</body></html>",
        escape(lang.split('-').next().unwrap_or("en")),
        sanitize(&messages.text(&format!("{body_key}BodyHtml"), &marked)),
    );
    Ok((subject, text, html))
}

/// Writes and sends a mail.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn deliver(
    state: &OidcState,
    realm: &RealmRecord,
    smtp: &SmtpSettings,
    recipient: &Recipient<'_>,
    headers: &HeaderMap,
    template: &Template<'_>,
    link: &str,
    lifespan: i32,
) -> Result<(), MailError> {
    let (subject, text, html) = compose(state, realm, recipient, headers, template, link, lifespan)
        .await
        .map_err(|_| MailError::Delivery)?;
    send(
        smtp,
        Mail {
            to: recipient.email,
            subject: &subject,
            text,
            html,
        },
    )
    .await
}

/// A plausible email address: one `@`, non-empty parts, a dotted domain.
pub(crate) fn valid_email(email: &str) -> bool {
    email.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty()
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && !domain.contains('@')
            && email.len() <= 255
            && !email.chars().any(|c| c.is_whitespace() || c.is_control())
    })
}

#[cfg(test)]
mod tests {
    use super::{choice, sanitize, valid_email};

    #[test]
    fn email_needs_one_at_and_a_dotted_domain() {
        assert!(valid_email("changed@example.invalid"));
        assert!(!valid_email("not-an-email"));
        assert!(!valid_email("@example.invalid"));
        assert!(!valid_email("a@localhost"));
        assert!(!valid_email("a@b@example.invalid"));
        assert!(!valid_email("a b@example.invalid"));
    }

    #[test]
    fn choices_follow_java_choice_format() {
        let units = "{0,choice,0#minutes|1#minute|1<minutes}";
        assert_eq!(choice(units, 0).as_deref(), Some("minutes"));
        assert_eq!(choice(units, 1).as_deref(), Some("minute"));
        assert_eq!(choice(units, 5).as_deref(), Some("minutes"));
        assert_eq!(choice("plain", 5), None);
    }

    #[test]
    fn sanitizing_keeps_paragraphs_and_web_links_only() {
        assert_eq!(
            sanitize(
                "<p>Hi <script>x</script><a href=\"https://e.test/a\" onclick=\"y\">go</a></p>"
            ),
            "<p>Hi x<a href=\"https://e.test/a\">go</a></p>"
        );
        assert_eq!(sanitize("<a href=\"javascript:x\">go</a>"), "<a>go</a>");
        assert_eq!(sanitize("1 < 2"), "1 &lt; 2");
    }
}
