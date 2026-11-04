# Pinned reference HTTP fixtures

Run `tests/reference/tokens.py --archive /path/to/keycloak-26.8.1.tar.gz` with Python 3.12+, OpenJDK 25 and OpenSSL; the launcher checks the archive digest from `compatibility/reference.lock`, starts an isolated temporary upstream server on loopback port 18081, and removes its realm/data after the run.

The suite compares 91 public HTTP observations with `token-observations.json`, covering public/confidential clients, token authentication, audience/ownership checks, access/refresh/ID/unknown tokens, expired access tokens, refresh/session effects, and metadata/token/userinfo CORS; token and claim values are excluded from the snapshot, so these observations do not establish full response or target parity.

The default `no-aud-owner` client has no audience mapper and cannot introspect its own access token as active; `conf-owner`, `conf-other` and `short-owner` have explicit self-audience mappers, and `public-owner` has a mapper adding `conf-other` to its access-token audience.

The shared-session fixture signs in two clients through the same real upstream SSO cookies and verifies that revoking one client's refresh token preserves the sibling client's access, refresh and userinfo; the short-token fixture uses an explicit one-second access-token lifetime, without claiming expired-refresh or offline-token coverage.

Synthetic bootstrap/client/user secrets and tokens remain in memory, upstream process output is suppressed, and snapshots retain only selected error/active fields, field names and response headers; the only header normalization replaces the random fixture realm in `WWW-Authenticate` with `{realm}`.

`--record` emits redacted observations without comparing the baseline for an explicit reviewed contract update; normal runs fail if the baseline is missing or any observed case changes, and `--port` selects another loopback reference port.

`oauth.py` separately tests public/confidential login forms, code/PKCE, signed token validation and client-authentication errors; the HTTP form client does not replace browser-engine or independent protocol-client qualification.

`service_accounts.py` uses the same launcher and records 21 client-credentials
observations in `service-account-observations.json`: post and Basic secrets,
openid and unknown scopes, public, disabled and unknown clients, origin checks,
userinfo scope rules, introspection and revocation effects. It retains response
field and claim names and only fixed values: token type, granted scope,
service-account username and access audience. The upstream token has no `sid`
claim, no refresh token and the default `account` audience.

`admin_realms.py` records 19 realm administration cases in
`admin-realm-observations.json`: create, read and delete with the bootstrap
service account, an unprivileged service account, an invalid token and no
token; duplicate, unnamed and malformed requests; and discovery for new,
disabled and deleted realms. It keeps status, content type, `Location`, error
messages and the 104 realm representation field names. Both new baselines
passed a second, comparing reference run.

`admin_users.py` records 21 user administration cases in
`admin-user-observations.json`: create, duplicate username (case-insensitive)
and email, missing username, default and explicit enabled state, read, exact
and prefix search, count, password reset, sign-in after reset, and delete. The
fixture user sets name and email because the default 26.8.1 user profile
requires them before a login completes. The baseline passed a second,
comparing run.

`admin_clients.py` records 23 client administration cases in
`admin-client-observations.json`: public, confidential and default clients,
duplicates, a client without `clientId` (the reference generates a UUID),
malformed and unauthenticated requests, read, `clientId` search, secret read
and regeneration, the service-account user and delete. Secrets are reduced to
presence. Every new realm lists six built-in clients (`account`,
`account-console`, `admin-cli`, `broker`, `realm-management`,
`security-admin-console`). The baseline passed a second, comparing run.

`admin_roles.py` records 21 realm role cases in `admin-role-observations.json`:
the default roles of a new realm, create, duplicate, unnamed and malformed
requests, read, list, user realm role mappings (add, repeat, unknown, remove)
and the users holding a role. Every new realm has `default-roles-{realm}`,
`offline_access` and `uma_authorization`, and new users hold the default
role. The baseline passed a second, comparing run.

`admin_groups.py` records 25 group cases in `admin-group-observations.json`:
top-level and child groups, duplicate names among top-level groups and
siblings, missing names, list, count, read, children, user membership (join,
repeat, unknown group, leave), members, and delete with its children. The
baseline passed a second, comparing run.

`logout.py` records 16 OIDC logout cases in `logout-observations.json`:
refresh-token POST logout (success, repeat, missing token, no client, another
client's token) and RP-initiated GET logout (registered and unregistered
post-logout redirects, missing and invalid `id_token_hint`, and no redirect),
each followed by refresh and userinfo checks of the ended session. Redirects
are observed without following them. The baseline passed a second, comparing
run.

`sso.py` records 10 SSO cases in `sso-observations.json`: the session cookies
after login, silent authorization for the same and another client,
`prompt=none` with and without a session, `prompt=login`, `max_age=0`, and
cookie clearing at logout. Only `KEYCLOAK_IDENTITY` and `KEYCLOAK_SESSION` are
kept, because Keycloak's per-login cookies vary between runs. The `max_age`
probe waits past the login second, since the reference compares whole
seconds. The baseline passed two comparing runs.

`consent.py` records 10 consent cases in `consent-observations.json` for a
`consentRequired` client: the consent screen after password login, deny
(`access_denied`), accept, remembered consent on a new login, `prompt=consent`,
and the admin consent list and revocation, after which the screen returns.
Pages are reduced to their kind and submit button names. The baseline passed a
second, comparing run.

`otp.py` records 13 TOTP cases in `otp-observations.json`: `CONFIGURE_TOTP`
setup with wrong, missing and correct codes, the admin credential list and
user flags afterwards, OTP login with wrong, correct and reused codes, and
login after the admin deletes the OTP credential. The probe computes codes
with Keycloak's defaults (HMAC-SHA1 over the secret string's bytes, 6 digits,
30-second steps) and waits for a fresh step before the login cases, so a run
takes about a minute of setup. Secrets and codes are never retained. The
baseline passed a second, comparing run.

`update_password.py` records 9 cases in `update-password-observations.json`:
an admin temporary password adds `UPDATE_PASSWORD`, login then shows
`kc-passwd-update-form`, mismatched and empty passwords show it again, success
continues to the code and clears the action, and only the new password signs
in. The reference also accepts the temporary password itself as the new one
under its default policy, so that case is not part of the baseline. A wrong
password shows the login form again with status 200. The baseline passed a
second, comparing run.

`execute_actions.py` records 12 cases in `execute-actions-observations.json`
for admin `execute-actions-email` with `UPDATE_PASSWORD`, delivered to the
shared in-memory SMTP sink in `tests/smtp_sink.py`: errors for a user without
email, a realm without SMTP settings and an unknown action; the multipart
message's headers and its `/login-actions/action-token?key=` link; the info
page, password form and confirmation page behind the link; reuse of the
link; and sign-in with the new password. Links, tokens and passwords are not
retained. The baseline passed a second, comparing run.

`reset_credentials.py` records 12 forgot-password cases in
`reset-credentials-observations.json`: the login-page link only when
`resetPasswordAllowed` is set, `kc-reset-password-form`, the same "you should
receive an email" login page for known and unknown usernames with mail only
for the known one, the "Reset password" message, the emailed link's password
form, its continuation into the original login with a code, link reuse, and
sign-in with the new password. The baseline passed a second, comparing run.

`verify_email.py` records 14 cases in `verify-email-observations.json` for a
`verifyEmail` realm: the page after the password with its resend link, the
"Verify email" message sent at login, the user's flag and action before and
after the link, the same-browser link continuing to the code, an "already
verified" page on reuse, admin `send-verify-email`, the "confirm validity"
page an admin-sent link shows before it verifies, and the unknown-user error.
Pages are reduced to form ids, fields and a few keyword phrases. The baseline
passed a second, comparing run.

`update_profile.py` records 6 `UPDATE_PROFILE` cases in
`update-profile-observations.json`: the prefilled `kc-update-profile-form`
(email, first and last name; username is not editable by default),
field errors for a missing first name and for an invalid or taken email,
success continuing to the code, and the stored user afterwards, whose email is
lowercased and no longer verified. The baseline passed a second, comparing
run.
