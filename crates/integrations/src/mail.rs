//! Realm email delivery over SMTP; see `docs/dependencies.md` for the review
//! of the lettre client and the limits placed on it.

use std::net::IpAddr;
use std::time::Duration;

use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// Longest a single delivery may take, connection included.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// A realm's SMTP settings, as in Keycloak's `smtpServer` representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtpSettings {
    /// SMTP server host name or address.
    pub host: String,
    /// SMTP server port.
    pub port: u16,
    /// Sender address.
    pub from: String,
    /// Optional sender display name.
    pub from_display_name: Option<String>,
    /// Upgrade a plain connection with STARTTLS.
    pub starttls: bool,
    /// Connect with implicit TLS.
    pub ssl: bool,
}

/// One message with plain-text and HTML alternatives.
pub struct Mail<'a> {
    /// Recipient address.
    pub to: &'a str,
    /// Subject line.
    pub subject: &'a str,
    /// Plain-text body.
    pub text: String,
    /// HTML body; callers escape interpolated values.
    pub html: String,
}

/// Why a message was not delivered; no message content is included.
#[derive(Debug, PartialEq, Eq)]
pub enum MailError {
    /// The configured sender address is missing or invalid.
    InvalidSender,
    /// The recipient address is invalid.
    InvalidRecipient,
    /// Plain SMTP was requested for a host that is not loopback.
    Insecure,
    /// The server refused the message or could not be reached in time.
    Delivery,
}

fn loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Checks settings without connecting: a valid sender, and TLS unless the
/// server is on this host.
pub fn validate(settings: &SmtpSettings) -> Result<Mailbox, MailError> {
    if !(settings.ssl || settings.starttls || loopback(&settings.host)) {
        return Err(MailError::Insecure);
    }
    let address = settings
        .from
        .parse()
        .map_err(|_| MailError::InvalidSender)?;
    Ok(Mailbox::new(settings.from_display_name.clone(), address))
}

/// Sends one message, waiting at most the send timeout.
pub async fn send(settings: &SmtpSettings, mail: Mail<'_>) -> Result<(), MailError> {
    let sender = validate(settings)?;
    let recipient: Mailbox = mail.to.parse().map_err(|_| MailError::InvalidRecipient)?;
    let message = Message::builder()
        .from(sender)
        .to(recipient)
        .subject(mail.subject)
        .multipart(MultiPart::alternative_plain_html(mail.text, mail.html))
        .map_err(|_| MailError::Delivery)?;
    let tls = || TlsParameters::new(settings.host.clone()).map_err(|_| MailError::Delivery);
    let tls = if settings.ssl {
        Tls::Wrapper(tls()?)
    } else if settings.starttls {
        Tls::Required(tls()?)
    } else {
        Tls::None
    };
    let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&settings.host)
        .port(settings.port)
        .tls(tls)
        .timeout(Some(SEND_TIMEOUT))
        .build();
    tokio::time::timeout(SEND_TIMEOUT, transport.send(message))
        .await
        .map_err(|_| MailError::Delivery)?
        .map(|_| ())
        .map_err(|_| MailError::Delivery)
}

#[cfg(test)]
mod tests {
    use super::{MailError, SmtpSettings, validate};

    fn settings(host: &str, from: &str, tls: bool) -> SmtpSettings {
        SmtpSettings {
            host: host.to_owned(),
            port: 25,
            from: from.to_owned(),
            from_display_name: Some("Realm".to_owned()),
            starttls: tls,
            ssl: false,
        }
    }

    #[test]
    fn plain_smtp_is_only_for_loopback() {
        assert!(validate(&settings("127.0.0.1", "a@example.test", false)).is_ok());
        assert!(validate(&settings("localhost", "a@example.test", false)).is_ok());
        assert!(validate(&settings("[::1]", "a@example.test", false)).is_ok());
        assert_eq!(
            validate(&settings("mail.example.test", "a@example.test", false)),
            Err(MailError::Insecure)
        );
        assert!(validate(&settings("mail.example.test", "a@example.test", true)).is_ok());
    }

    #[test]
    fn sender_must_be_an_address() {
        assert_eq!(
            validate(&settings("127.0.0.1", "", false)),
            Err(MailError::InvalidSender)
        );
        assert_eq!(
            validate(&settings("127.0.0.1", "not an address", false)),
            Err(MailError::InvalidSender)
        );
    }
}
