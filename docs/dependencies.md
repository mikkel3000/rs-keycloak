# Dependency reviews

PLAN.md requires a recorded license and security review before depending on
mail, crypto, XML/SAML, WebAuthn, LDAP and template libraries. Each entry
names the exact pinned version, why it is needed, what it pulls in and the
limits placed on its use.

## lettre 0.11.23 (SMTP client)

- Purpose: deliver realm email (execute-actions, later password reset and
  email verification) over SMTP from the Rust backend, as PLAN.md's
  integrations crate requires. Writing an SMTP client and MIME builder is not
  justified when a maintained one exists.
- License: MIT. Published 2026-08-03, not yanked, and older than two weeks
  when adopted.
- Features: `default-features = false` with `builder`, `smtp-transport`,
  `tokio1`, `tokio1-rustls`, `ring` and `webpki-roots`. This keeps TLS on
  rustls with the `ring` provider already used for signing, and excludes
  native-tls, OpenSSL, aws-lc, sendmail and file transports.
- New crates in `Cargo.lock`: async-trait, base64 0.23, email-encoding,
  email_address, fastrand, lettre, nom, quoted_printable and tokio-rustls,
  all under MIT, Apache-2.0 or 0BSD. rustls and webpki-roots were already
  present through sqlx.
- Use limits: only `crates/integrations` depends on it. Messages are built
  from fixed templates with escaped values; recipient and sender addresses
  are parsed by lettre before sending. Plain SMTP without TLS is allowed only
  to loopback hosts, so credentials and links never cross a network
  unencrypted. Sends have a bounded timeout.
- Review owner: the coordinator in IMPLEMENTATION.md; re-review on any
  version change.
