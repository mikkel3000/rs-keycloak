//! Realm email shared by the admin API and login pages: SMTP settings from
//! the realm record, action links and the fixed English messages.

use rs_keycloak_integrations::mail::{Mail, MailError, SmtpSettings, send};
use rs_keycloak_storage_postgres::RealmRecord;

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

/// Escapes text for an HTML body.
pub(crate) fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Describes a lifespan the way the reference's messages do.
pub(crate) fn expiry(seconds: i32) -> String {
    match seconds / 3600 {
        0 => format!("{} minutes", (seconds / 60).max(1)),
        hours => format!("{hours} hours"),
    }
}

/// Sends the "Verify email" message with a link.
pub(crate) async fn send_verification(
    settings: &SmtpSettings,
    realm: &str,
    to: &str,
    link: &str,
    lifespan: i32,
) -> Result<(), MailError> {
    let expiry = expiry(lifespan);
    let text = format!(
        "Someone has created a {realm} account with this email address. If this was you, click the link below to verify your email address\n\n{link}\n\nThis link will expire within {expiry}.\n\nIf you didn't create this account, just ignore this message."
    );
    let html = format!(
        "<p>Someone has created a {realm} account with this email address. If this was you, click the link below to verify your email address</p><p><a href=\"{link}\">Link to e-mail address verification</a></p><p>This link will expire within {expiry}.</p><p>If you didn't create this account, just ignore this message.</p>",
        realm = escape(realm),
        link = escape(link),
    );
    send(
        settings,
        Mail {
            to,
            subject: "Verify email",
            text,
            html,
        },
    )
    .await
}
