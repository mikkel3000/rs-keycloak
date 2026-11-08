# Implementation coordination

The complete scope and release gates in PLAN.md remain required; no work package constitutes a production release.

## Active work packages

| Owner | Files | Current task |
| --- | --- | --- |
| Sol: contract | compatibility/, tests/reference/ | Resolved HTTP inventory and OAuth reference tests |
| Terra: foundation | Root Cargo/toolchain files, crates/server/, crates/http/, docs/rust-style.md | Public authorization-code PKCE flow, signing and server integration |
| Terra: storage | crates/storage-postgres/, migrations/ | Atomic OAuth grants and PostgreSQL constraints |
| Coordinator | Integration, runtime evidence and this record | Resolve interfaces, verify public behavior and schedule remaining scope |

Foundation owns shared Cargo edits; storage and foundation agree on interfaces before integration, and agents must not overwrite each other's changes.

## Required follow-on work

After the initial integration, execute identity/admin, full authentication/account flows, all remaining protocol families, Rust provider SDK/host, web interface, migration/setup, recovery, multi-node operation and the complete production qualification in PLAN.md.

Public CLI/API/reference behavior is the first verification boundary; passing compilation or a scaffold smoke test cannot count as protocol parity, recovery proof or production readiness.

## Verified evidence (2026-11-02)

The current Rust workspace builds; ten public CLI tests pass, including remote TLS requirements, private management defaults, input redaction and config validation without a database connection.

`tests/public/database.sh` passed against the platform-specific PostgreSQL image in `compatibility/reference.lock`: fresh schema refusal, repeat migration, corrupt-history refusal without changing maintenance state, failed-DDL quarantine and successful recovery after repair.

The database harness now uses an immutable image digest and fails explicitly on readiness timeout; the test creates and removes its own isolated container.

These checks do not prove authentication, HTTP parity, full recovery or any production release gate; the server still lacks complete authentication flows.

Delegation resumed with Sol and Terra after the usage limit cleared. Public authorization-code flow integration and reference coverage remain in progress.

`tests/public/lifecycle_contract.py` passed through the `serve` command against the isolated database: liveness 200, readiness 503 while authentication is incomplete, wrong-method 405, no public realm route on the management port, clean SIGTERM exit and socket release. This test is committed as `18fde34`.

Database URL security regression checks reject alternate TLS query aliases, host overrides and connection options that bypass durability policy (`6c760e1`). Guarded password login state and RFC 7636 S256 validation are committed (`c327817`); neither proves a complete public OAuth flow.

## Public OAuth evidence (2026-11-03)

The public PostgreSQL-backed fixture now passes browser-form password login with
cookie binding, code/S256 exchange, independent RS256 verification against JWKS,
nonce/issuer/audience checks, session-checked userinfo, code replay rejection,
refresh rotation, refresh replay revocation, and a two-request refresh race with
exactly one success. It checks both old and newly issued access tokens become
unusable at userinfo after refresh replay. The fixture uses local HTTP transport
behind the configured HTTPS issuer; it does not prove browser-engine behavior,
TLS proxy deployment, complete Keycloak parity or production readiness.

Refresh currently supports public clients and the openid scope, with fixed
session lifetime and mandatory rotation; configurable Keycloak refresh policy,
confidential clients, offline sessions and full scope handling remain required.
All three delegated agents stopped at a usage limit; changes are saved and the
coordinator is continuing locally.

## Issuer path and confidential-client checks

Public tests now exercise both the root issuer and `/auth/tenant`, including
discovery, login form targets, cookie paths, signed claims, token exchange,
refresh and userinfo. The prefix test first failed because the router ignored
the configured path. Routing now mounts below that prefix and generated login
actions and cookies use it. Invalid raw cookie/routing delimiters fail config
validation instead of reaching router construction.

The same HTTP fixture checks confidential clients with Basic and form secrets,
repeat CLI setup, exact pinned authentication failures, and CLI secret rotation:
the old secret fails while the new secret can refresh an existing grant.
Per-token revocation storage is committed; userinfo reads it, but revocation and
introspection HTTP endpoints and their full reference checks remain unfinished.

## Introspection and adapter gap

Public HTTP tests pass introspection of current access/refresh tokens, unknown
and revoked tokens, public-client denial, wrong-audience denial, missing token,
unsupported hints and failed confidential authentication, at both issuer paths.
The handler follows the pinned TokenIntrospectionEndpoint source for the covered
cases; complete upstream claim/mapper parity is not yet proved.

The opaque refresh-token gap is fixed: refresh tokens are signed RS256 JWTs
with a Refresh type, issuer audience, client/session binding, unique jti and the
stored family's fixed expiry. Storage hashes token IDs only after JWT validation;
rotation and replay remain atomic. Access and refresh verifiers require distinct
types. Public tests check independent refresh signatures, type substitution,
unchanged expiry across rotation and rejection of revoked sessions.

The digest-pinned keycloak-js 26.2.2 adapter now loads issued tokens and performs
real HTTP refreshes against both issuer paths in the Node client harness.
Credentials stay in private pipes and memory. The fixture now also lets the adapter generate an authorization request,
submits the login form, and processes its default fragment callback through the
real token endpoint. Iframe/session checks, CORS and full browser behavior still
need implementation and browser-engine qualification.


## Authorization response modes

Migration 9 binds query, fragment or form_post to each authorization request;
password submission cannot change the saved response mode. Responses include
issuer identification and preserve state. Form-post responses use escaped
hidden fields, a nonce-scoped auto-submit script, a registered-origin form
policy and no-store headers. The script runs in the client; backend execution
remains Rust. Public tests pass all three modes, malicious HTML characters in
state, and the pinned adapter's fragment callback at both issuer paths.

## Revocation and browser origins

The revocation route follows the pinned TokenRevocationEndpoint for the recorded
cases: duplicate parameters, missing token, unsupported ID tokens, unknown
tokens as 200 `invalid_token`, client authentication errors and "Unmatching
clients" ownership. Access revocation stores the token ID until expiry; refresh
revocation ends the family and the client session, and ends the user session
only when no sibling client session remains.

Clients register exact canonical web origins through the CLI. Token,
introspection, revocation and userinfo requests carrying an unregistered origin
fail with 403 before any token state changes; preflights answer any canonical
origin with the reference header list, and discovery and certs allow any origin.
Unit tests compare preflight and metadata CORS headers with every recorded
reference observation without a database. The database-backed revocation, race
and CORS public tests in `tests/public/oidc_contract.py` exceed the 500 ms test
budget and were not re-run for this record; the commit `23f960f` reports them
passing.

Userinfo follows the pinned UserInfoEndpoint order: every origin is allowed
until a token with a valid signature names its client, then that client's
registered origins apply. Missing tokens get `Bearer realm="<realm>"`; failed
signatures and revoked tokens get "Token verification failed"; missing sessions
get "user_session_not_found", matching the recorded challenges. Preflights send
the reference one-hour max age. `tests/public/userinfo_contract.py` checks these
cases through HTTP with independently signed tokens; each case takes under
50 ms after one shared server start. A verified token naming an unknown client
gets "Client not found" from any origin, as in the reference; disabled clients
and users still report "user_session_not_found" instead of the reference's
"Client disabled" and "User disabled", because no public command can disable
them yet.

## Client-credentials grant

`client enable-service-account <realm> <client-id>` enables service accounts on
an existing confidential client and creates its `service-account-<client-id>`
user once; public clients are refused, and the database also requires
confidential clients through a check constraint. The token endpoint follows the
pinned ClientCredentialsGrantType and the 21 recorded cases in
`tests/reference/service-account-observations.json`. Public, disabled and
unknown clients get the recorded errors. Tokens carry no `sid`, no refresh token
is issued, and an ID token without `auth_time` is added only for `openid`.
Userinfo needs `openid` and answers 403 `insufficient_scope` otherwise;
revocation of a sessionless token takes effect at userinfo and introspection,
while new grants keep working.

Sessionless tokens are checked against the client's current service-account
user rather than a stored session, and their revocations bind that user, so
deleting the client removes them. `tests/public/client_credentials_contract.py`
checks 13 cases through HTTP; the slowest takes 88 ms.

Remaining differences from the reference: access tokens name the client as
audience, where Keycloak's default role mappings produce `account`, so the
owner can introspect its own token as active; only `openid` is grantable, so a
default request returns an empty scope instead of `profile email`; access and
ID tokens omit Keycloak's role, profile and client-address claims; enabling a
service account through the CLI writes no audit event, like the other CLI
provisioning commands.

## Realm administration

`client grant-master-admin <client-id>` grants the master `admin` role to a
master client's service account, which then calls the admin API with
client-credentials tokens, as Keycloak's bootstrap admin client does. User
tokens from the master realm work the same way when the user holds that role.
`POST /admin/realms`, `GET /admin/realms/{realm}` and
`DELETE /admin/realms/{realm}` follow the 19 recorded cases in
`tests/reference/admin-realm-observations.json` and the pinned
RealmAdminResource: 401 and 403 bodies, 201 with `Location`, 409 for
duplicates, `errorMessage` validation errors, 404 for unknown realms, and 400
when deleting master. Discovery now answers 404 "Realm does not exist" for
unknown realms, still serves disabled realms, and sends the reference cache
header. Realm creation and deletion write audit events in the master realm
under the acting user, so the record outlives the deleted realm.
`tests/public/admin_realms_contract.py` checks 10 cases; the slowest takes
74 ms.

Remaining differences: the representation holds only `id`, `realm` and
`enabled` of the reference's 104 fields; requests with any other field are
refused with 400 instead of being partly applied; realm names follow the
existing URL-safe pattern and other names get "Invalid realm name", a message
the reference was not recorded for; admin tokens must come from the master
realm, and the fine-grained realm-management roles are not modelled.

## User administration

`/admin/realms/{realm}/users` supports create, exact and contains username
search with `first` and `max`, `count`, read, delete and
`reset-password`, following the 21 recorded cases in
`tests/reference/admin-user-observations.json`. Usernames and emails are stored
lowercased and are unique per realm. A user created without `enabled` is
disabled. Duplicate, missing-name, malformed-JSON, unknown-user and
empty-password errors use the recorded bodies. Search and count exclude
service-account users. Password resets hash with Argon2id behind a two-slot
limit and replace the single password credential; pending login challenges for
the old credential are removed with it. Creation, deletion and resets are
audited in the master realm under the acting user.
`tests/public/admin_users_contract.py` checks 6 groups of cases, including
browser login in a new realm after a reset; the slowest takes 162 ms.

Remaining differences: the representation omits Keycloak's `access` map, and
always reports no TOTP, required actions or disableable credential types,
because none of those exist yet; other user fields, other search parameters
and temporary passwords are refused with 400; deleting a master user who has
written audit events fails, because audit rows keep their actor.

## Client administration and recoverable secrets

Client secrets created or regenerated through the admin API are sealed with
AES-256-GCM under the operator key `RS_KEYCLOAK_SECRET_KEY` (32 bytes in
base64), as PLAN.md requires for recoverable secrets. The client row's realm
and identifier are bound as associated data, and the key's non-secret
identifier is stored beside the ciphertext. Authentication opens the secret and
compares SHA-256 digests. Secrets set through the CLI remain Argon2id hashes,
which still authenticate but cannot be returned; regenerating such a secret
through the admin API converts it to a sealed one. Without the key, creating a
confidential client through the API answers 503, and clients with sealed
secrets cannot authenticate.

`/admin/realms/{realm}/clients` supports create, list with `clientId`, read,
delete, `client-secret` read and regeneration, and `service-account-user`,
following the 23 recorded cases in
`tests/reference/admin-client-observations.json`. Defaults match the
reference: a confidential client with standard flow and a generated secret,
and a generated `clientId` when none is given. `standardFlowEnabled: false`
now blocks authorization requests. Regenerating a secret bumps the client
revision, so the old secret stops working at once.
`tests/public/admin_clients_contract.py` checks 7 groups of cases; the slowest
takes 165 ms. Redirect URI and web origin rules moved to
`rs_keycloak_protocols::client_urls`, shared by the CLI and the API; the API
does not allow loopback HTTP.

Remaining differences: the representation lists only the 13 modelled
settings of the reference's 26 fields; direct access, implicit, non-OIDC
protocols, other authenticators and attributes other than S256 PKCE and
post-logout redirect URIs are refused; the CLI cannot rotate a sealed
secret.

## Realm roles and role mappings

Every realm has `default-roles-{realm}` (composite of `offline_access` and
`uma_authorization`), and every user, including bootstrap and service-account
users, holds it. PostgreSQL triggers on realm and user inserts enforce this,
so no creation path can skip it, and migration 14 backfilled existing realms
and users. A fresh install checked this: the bootstrap admin holds `admin` and
`default-roles-master`.

`/admin/realms/{realm}/roles` supports list, create, read, delete and the
users holding a role; `/users/{id}/role-mappings/realm` supports read, add and
remove. These follow the 21 recorded cases in
`tests/reference/admin-role-observations.json`. Mappings are matched by both
role identifier and name, as the reference does. Adding a mapping twice
changes nothing. Changes are audited in the master realm.
`tests/public/admin_roles_contract.py` checks 3 groups of cases; the slowest
takes 155 ms.

Access tokens from the authorization-code, refresh and client-credentials
grants carry the user's effective realm roles in `realm_access.roles`: direct
grants plus composites, expanded recursively to 32 levels, sorted. The
contracts check this for browser login, master and new-realm service
accounts, and a granted role.

Remaining differences: role attributes are refused (composite editing came
later, see below); deleting the default role answers 400, a response the reference was not
recorded for. Client roles, `resource_access` and group roles came later
(see below).

## Groups

`/admin/realms/{realm}/groups` supports list, count, create, read, delete,
children and members; `/users/{id}/groups` supports list, join and leave.
These follow the 25 recorded cases in
`tests/reference/admin-group-observations.json`. Groups form a tree.
Uniqueness among top-level groups and among siblings is enforced by partial
unique indexes, paths come from a recursive SQL function limited to 64
levels, and deleting a group removes its subgroups and memberships through
cascades. Changes are audited in the master realm.
`tests/public/admin_groups_contract.py` runs the recorded sequence in 329 ms.

Remaining differences: representations omit the `access` map; group
attributes, group role mappings, moving groups and search parameters are
refused or missing; group membership is not yet used in tokens or
authorization.

## Logout

`/realms/{realm}/protocol/openid-connect/logout` follows the 16 recorded cases
in `tests/reference/logout-observations.json`. A POST with a refresh token from
the owning client ends the token's session and all its refresh families, and
answers 204; repeating it is harmless, another client's token is
`invalid_grant`, and a POST without a refresh token is a browser logout. GET
logout verifies `id_token_hint` (signature and issuer, ignoring expiry), ends
its session, and redirects only to a post-logout URI registered with the
client's `post.logout.redirect.uris` attribute (`+` accepts the client's
redirect URIs), adding just `state`; otherwise it answers with an HTML page.
After logout, refresh is `invalid_grant` and userinfo is
"user_session_not_found", as recorded. ID tokens now carry `sid`, and
discovery lists `end_session_endpoint`. `tests/public/logout_contract.py`
checks 3 groups of cases; the slowest takes 227 ms. The fixture now provides
an `AdminCase` base class and a shared browser login.

Remaining differences: browser logout now asks for confirmation and ends
the SSO cookie's session, see "Info and error pages"; front-channel and back-channel logout
notifications to other clients are not implemented. A refresh token whose
session has ended (logout, revocation) now gets the recorded "Session not
active" description; replayed and unknown refresh tokens keep a bare
`invalid_grant` until their reference responses are recorded.

## Browser SSO

A successful password login sets `KEYCLOAK_IDENTITY` (HttpOnly, a random
token whose SHA-256 digest is stored on the user session) and
`KEYCLOAK_SESSION` (the session ID, readable by scripts, with the session's
lifetime), both Secure, SameSite=None and scoped to `{prefix}/realms/{realm}/`,
as in the 10 recorded cases of `tests/reference/sso-observations.json`. An
authorization request with a live session issues a code without the form, for
the same or another client, which joins the session; code callbacks now carry
`session_state`. `prompt=none` without a session redirects with
`login_required`; `prompt=login` and an elapsed `max_age` show the form.
Logout with `id_token_hint` clears both cookies with the reference's bare
clearing form. `tests/public/sso_contract.py` checks 4 groups of cases; the
slowest takes 217 ms. The `max_age=0` case needs a one-second wait, so its
whole-second rule is unit-tested instead.

Remaining differences: Keycloak's per-login cookies (`AUTH_SESSION_ID`,
`KC_RESTART`, `KC_AUTH_SESSION_HASH`) are not reproduced, since this server
keeps login state in its own CSRF cookie; other `prompt` values
(`consent`, `select_account`) are ignored; the session iframe and
`check_session_iframe` are not implemented.

## Consent

Clients created with `consentRequired: true` show a consent form (`accept`,
`cancel`) after password login or from a live SSO session, unless the user
already consented to that client; `prompt=consent` asks again. The form is
bound to the login request's CSRF cookie and the session waiting on it is
stored on the authorization request. Accept stores the consent and issues the
code; cancel consumes the request and redirects with `access_denied`.
`/users/{id}/consents` lists consents and `DELETE .../consents/{client}`
revokes one, with the pinned source's 404 messages for unknown clients and
missing consents. These follow the 10 recorded cases in
`tests/reference/consent-observations.json`;
`tests/public/consent_contract.py` checks 3 groups, the slowest in 257 ms.

Remaining differences: granted scopes list the requested scope (`openid`)
rather than Keycloak's default client scopes; the consent page is a plain
form, not Keycloak's theme; consents are not yet audited or shown in an
account console.

## TOTP second factor

Users created with `requiredActions: ["CONFIGURE_TOTP"]` get a setup form
(`kc-totp-settings-form`) after their password, and users with an OTP
credential get a code form (`kc-otp-login-form`), following the 13 recorded
cases in `tests/reference/otp-observations.json`. Codes use Keycloak's default
policy (HMAC-SHA1 over the secret's bytes, 6 digits, 30-second steps, one step
either side), checked against RFC 6238 vectors, and each step is accepted
once, so a code cannot be replayed. Seeds are sealed with
`RS_KEYCLOAK_SECRET_KEY`, bound to their realm and credential, and are never
returned. The session created by the password step is marked pending: code
issue and SSO refuse it until the second factor passes, so a password alone
yields neither a code nor an SSO cookie. The user representation now reports
`totp`, `requiredActions` and `disableableCredentialTypes`, and
`/users/{id}/credentials` lists and deletes credentials.
`tests/public/otp_contract.py` checks the recorded sequence in 340 ms using the
next step's code instead of the reference's 30-second wait.

Remaining differences: one OTP credential per user; HOTP, other OTP policies,
WebAuthn and recovery codes are not implemented; setup trusts the posted
secret as the reference does.

## Temporary passwords and login steps

An admin password reset with `temporary: true` adds `UPDATE_PASSWORD`; a
permanent reset clears it. The next login shows `kc-passwd-update-form`,
re-shown for mismatched or empty input, and success replaces the password,
clears the action and continues, following the 9 recorded cases in
`tests/reference/update-password-observations.json`. Login steps now run in
the reference order through one continuation: an existing OTP code first,
then `CONFIGURE_TOTP`, then `UPDATE_PASSWORD`. The session flag was renamed
`steps_pending` and stays set until every step has passed, with OTP
verification recorded separately. A wrong password now shows the login form
again with status 200, as recorded, instead of a bare 401.
`tests/public/update_password_contract.py` checks 3 groups, including the step
order for a user with both actions; the slowest takes 303 ms.

Remaining differences: password policies (length, history, complexity) are
not implemented, so the reference's acceptance of the temporary password as
the new one is matched only by default. The `logout-sessions` checkbox on the
password-update and TOTP-setup forms now ends the user's other sessions when
set to `on`, as in the pinned UpdatePassword and UpdateTotp actions.

## Realm email and action links

Realms accept Keycloak's string-valued `smtpServer` settings (`host`, `port`,
`from`, `fromDisplayName`, `starttls`, `ssl`) at creation and through a new
partial `PUT /admin/realms/{realm}`, and return them on read. Mail goes
through `crates/integrations` with lettre, reviewed in `docs/dependencies.md`;
plain SMTP is allowed only to loopback hosts, and each send has a 10-second
limit. `PUT /users/{id}/execute-actions-email` with `UPDATE_PASSWORD` follows
the 12 recorded cases in `tests/reference/execute-actions-observations.json`:
the recorded 400 and 500 errors, a multipart "Update Your Account" message
from the realm's sender, and a `/login-actions/action-token?key=` link that
opens an info page, then the password form, then a confirmation. Keys are
random, stored only as digests, expire after the requested `lifespan`
(default 12 hours), and are used once in the same transaction that replaces
the password. `tests/public/execute_actions_contract.py` runs the sequence
against the shared SMTP sink in `tests/smtp_sink.py`; the slowest case takes
307 ms.

Remaining differences: only `UPDATE_PASSWORD` can be sent (other known
actions answer 400); SMTP authentication is refused until its password can
be stored sealed; sends are synchronous, as in the reference, rather than
queued in a durable outbox; message text is fixed English, not a theme;
`client_id` and `redirect_uri` link parameters are ignored.

## Forgot password

Realms with `resetPasswordAllowed` (set at creation or through realm PUT)
show a "Forgot Password?" link on the login page, following the 12 recorded
cases in `tests/reference/reset-credentials-observations.json`. The
`kc-reset-password-form` takes a username or email. Every request returns the
same login page with "You should receive an email shortly with further
instructions.", and delivery failures are not shown, so the flow does not
reveal which accounts exist. Known enabled users with an email get a
"Reset password" message whose link is bound to the login request, expires
after 5 minutes, and opens the password form directly. In the browser that
started the login, a new password continues that login, through any pending
OTP or required-action steps, to the client's code; elsewhere it ends on the
confirmation page. `tests/public/reset_credentials_contract.py` checks 3
groups; the slowest takes 333 ms.

Remaining differences: links carry only `key`, without the reference's
`client_id`, `tab_id`, `execution` and `client_data` parameters; the reset
form is reachable only from a live login request; there is no rate limit on
reset requests per user yet.

## Email verification

Realms with `verifyEmail` add `VERIFY_EMAIL` to an unverified user with an
email when a session starts; one SQL function, `rs_prepare_login_steps`,
prepares every new session's steps, so password login and email-link logins
behave the same. The step runs after TOTP and password steps, as Keycloak's
default priorities order them. It sends a "Verify email" message with a link
bound to the login request (5 minutes) and shows a waiting page with a resend
link. In the same browser the link verifies the address, clears the action
and continues the login to the client's code; elsewhere, and for admin
`send-verify-email` links (12 hours), the user first confirms, then the
address is verified. A used link of a verified user shows an "already
verified" page with 200, as recorded. These follow the 14 recorded cases in
`tests/reference/verify-email-observations.json`;
`tests/public/verify_email_contract.py` checks 2 groups, the slowest in
311 ms. SMTP settings, links and message escaping now live in one `mail`
module shared by admin and login handlers.

Remaining differences: user profile updates (`UPDATE_PROFILE`) and changing an
email from an account console are not implemented, so a verified address can
only change through the admin API, which does not reset verification.

## Profile update

Users with `UPDATE_PROFILE` (set at creation through the admin API) review a
prefilled `kc-update-profile-form` with email, first and last name after
their password, following the 6 recorded cases in
`tests/reference/update-profile-observations.json`. Missing names, an
invalid email and another user's email re-render the form with that field's
`input-error-*` message. Success stores the email lowercased and, if it
changed, unverified; in a realm that verifies email, the user must then
verify the new address in the same login. The step runs after password steps
and before email verification, as Keycloak's default priorities order them.
`tests/public/update_profile_contract.py` runs the sequence in 242 ms. The
OTP contract was split so its login case no longer repeats the setup checks;
its slowest case now takes 383 ms.

Remaining differences: the user profile is fixed to username, email, first
and last name; configurable profile attributes are not implemented. The
username settings are applied since "Realm settings in the login flow".

## Account REST API

`/realms/{realm}/account` serves a user's own profile (read and update),
credential list and sessions (list and end), following the 10 recorded cases
in `tests/reference/account-api-observations.json`. Any access token of the
realm from a live user session works, as in the reference, if the user holds
the realm's default role, which is how Keycloak's account roles reach users.
Profile updates share the login-step rules: email uniqueness, lowercase
storage, loss of verification on change, and `VERIFY_EMAIL` where the realm
requires it. Errors use the reference's 409 `emailExistsMessage` and 400
`error-user-attribute-required` bodies, and the username is read-only.
`tests/public/account_api_contract.py` checks 2 groups, the slowest in
337 ms. Email validation is shared with the login pages through the `mail`
module.

Remaining differences: realms have no built-in `account-console` client or
account client roles, so access follows the default role instead; sessions
report no IP address, browser or separate last-access time; linked accounts,
applications, consents and credential removal through the account API are
not implemented; see "Account console" for the web interface.

## Client roles and built-in clients

Roles may belong to a client; names are unique per realm or per client
through partial unique indexes. Every realm, including existing ones through
migration 25, has the public built-in clients `account`, `account-console` and
`admin-cli`, the eight `account` roles, and the default role's composites
(`view-profile`, `manage-account`, which includes `manage-account-links`).
`/clients/{id}/roles` and `/users/{id}/role-mappings/clients/{client}` follow
the 19 recorded cases in `tests/reference/client-role-observations.json`, and
access tokens carry `resource_access`. The account API now checks the real
`account` roles: `view-profile` or `manage-account` to read, `manage-account`
to change. `tests/public/client_roles_contract.py` checks 2 groups, the
slowest in 381 ms; a fresh install with bootstrap creates the built-ins.

Remaining differences (built-in client URLs came later, see below): token `aud` still names the token's own client rather
than the clients whose roles it carries.

## Bearer-only clients

Clients may be bearer-only, set through `bearerOnly` at creation. Such a
client may authenticate only to introspection; the authorization endpoint
shows a 403 page, and the token, revocation and logout endpoints answer
`invalid_client` "Bearer-only not allowed" after the client authenticates.
Every realm, including existing ones through migration 26, now has the
bearer-only `broker` (role `read-token`) and `realm-management` (22 roles;
`realm-admin` includes the other 21, `view-users` includes `query-users` and
`query-groups`, `view-clients` includes `query-clients`) clients, which have
no secret and so cannot authenticate, and the public
`security-admin-console`. `GET .../roles/{role}/composites` lists a realm or
client role's direct composites. This follows the 23 recorded cases in
`tests/reference/bearer-only-observations.json`;
`tests/public/bearer_only_contract.py` checks 4 groups, the slowest in
259 ms.

Remaining differences: the authorization endpoint checks PKCE and other
request parameters before it checks for a bearer-only client, where the
reference checks the client first; the logout refusal is applied by analogy with the token and revocation
endpoints and was not recorded.

## Client updates

`PUT /admin/realms/{realm}/clients/{id}` applies a partial representation,
following the 27 recorded cases in
`tests/reference/admin-client-update-observations.json`: absent fields keep
their values, a body `id` is ignored, and a taken `clientId` answers 409
"Duplicate resource error". Creation and update share one settings parser
over either the creation defaults or the stored client, so both accept and
refuse the same fields. A rename renames the service-account user; enabling
service accounts creates that user if missing; becoming public drops the
secret and becoming confidential seals a new one. Every update bumps the
client revision, so authentications in flight with old settings fail. A
client created with redirect URIs and no web origins now gets their
origins, as in the reference. `tests/public/admin_client_update_contract.py`
checks 3 groups, the slowest in 263 ms.

Remaining differences (`rootUrl`, `baseUrl`, `name` and `description` came
later, see "Realm and client settings in the account console"): other
unmodelled fields are refused rather than stored; a client changed to
confidential that has a hashed secret from the CLI keeps it.

## Realm-scoped admin access

Tokens issued by a realm now reach that realm's admin API through the
user's effective `realm-management` roles, following the 228 recorded cases
in `tests/reference/admin-permission-observations.json`. Each handler names
the access it needs (query, view or manage of users, groups, clients or the
realm); `manage-*` implies view and query, `view-users` covers groups, client
roles need client access and realm roles realm access. Any role reads the
realm, in the reference's brief form without `view-realm`, and
`GET /admin/realms` (new) lists only the token's realm. Master `admin` tokens
still reach every realm, and only they create or delete realms. A token from
any other realm answers 403. All realms share the signing key, so the
issuer is read from the verified token rather than tried realm by realm.

Admin events now record the actor's own realm. Migration 27 drops the
actor's foreign key, so deleting a user who acted keeps the history (this
also lets acting master admins be deleted, which failed before), and makes
events go with their realm. `tests/public/admin_permissions_contract.py`
checks every role in its own test against one shared managed realm, the
slowest in 352 ms.

Remaining differences: the brief realm form uses default values, since only
field names were recorded, and lacks `displayName`, which is not stored;
master per-realm clients (`{realm}-realm`) and fine-grained admin
permissions are not modelled; the full realm representation still has 5 of
the reference's 104 fields; realm deletion by a realm's own `manage-realm`
was not recorded and is refused.

## Group role mappings

Groups hold realm and client roles under `/groups/{id}/role-mappings/realm`
and `.../clients/{client}`, following the 20 recorded cases in
`tests/reference/group-role-observations.json`. Members' effective roles,
used for tokens, the account API and admin access, now include the roles of
each of their groups and those groups' ancestors; one shared query builds
them. `/users/{id}/role-mappings/realm/composite` (and the client form)
lists a user's effective roles, while direct mappings and a role's user list
leave group roles out. A group read lists its `realmRoles` and
`clientRoles`. Users and groups share the mapping storage and handlers
through a role holder. `tests/public/group_roles_contract.py` checks 2
groups, the slowest in 423 ms.

Remaining differences: subgroup lists show empty `realmRoles` and
`clientRoles`, because mapped roles are read only for a single group.

## Composite role editing

`POST` and `DELETE /roles/{name}/composites` (and the client role form) add
and remove children from any container of the realm, and composites are
listed in all, `/realm` and `/clients/{client}` forms, following the 24
recorded cases in `tests/reference/role-composite-observations.json`. As in
the reference, repeats answer 204, a role may include itself, and cycles are
accepted; the effective-role query bounds its depth, so cycles end. A role
may be created with `composites` (realm names and client names by public
client identifier), resolved in the creating transaction, which rolls back
if a name is unknown. `RoleNames` (renamed from `EffectiveRoles`) carries
role names by container for effective roles, group reads and these
requests. `tests/public/role_composites_contract.py` checks 4 groups, the
slowest in 425 ms.

Remaining differences: an unknown composite at creation answers 404 "Could
not find composite role", a response the reference was not recorded for.

## User updates

`PUT /admin/realms/{realm}/users/{id}` applies a partial representation,
following the 26 recorded cases in
`tests/reference/admin-user-update-observations.json`. Creation and update
share one parser over the creation defaults or the stored user, so both
lowercase and validate email (400 `error-invalid-email` with its `field`,
which creation did not check before) and accept the same fields. An admin
email change keeps `emailVerified`, unlike the account API; an empty name
or email removes it; `requiredActions` replaces the list; the username is
read-only (400 `error-user-attribute-read-only`) unless unchanged; a body
`id` is ignored. Disabling stops browser login until the user is enabled.
`tests/public/admin_user_update_contract.py` checks 4 groups, the slowest in
335 ms.

Remaining differences: attributes and user-profile configuration are not
modelled, so other fields are refused, and `editUsernameAllowed` cannot be
turned on.

One unexplained failure was seen once while running every contract: a
`view-users` permission case answered 401 mid-test and did not reproduce in
24 runs. Token checks reject an `iat` later than the server clock, so a
clock step backwards would explain it; this is not confirmed.

## Combined role mappings

`GET /users/{id}/role-mappings` and `/groups/{id}/role-mappings` return a
holder's `realmMappings` and `clientMappings` together, each left out when
empty, with client mappings keyed by public client identifier, following
the 6 recorded cases in `tests/reference/role-mapping-observations.json`.
One query reads every mapping with its client's identifier.
`tests/public/role_mappings_contract.py` checks them in 353 ms.

## Redirect URI matching and client URLs

Clients may have `rootUrl` and `baseUrl`, and registered redirect URIs may
be relative to the root URL or end in `/*`, following the 19 recorded
cases in `tests/reference/redirect-matching-observations.json`. The
authorization endpoint now reads the client's rules, checks bearer-only
first as the reference does, and matches in Rust
(`rs_keycloak_protocols::client_urls::redirect_matches`): `X/*` matches `X`
and anything below `X/` with any query, but not user info or dot segments
(also percent-encoded); other URIs match exactly; fragments never match.
`${authBaseUrl}` and `${authAdminUrl}` resolve to the issuer base.
Authorization requests and codes keep the requested URI for the token
exchange and the matched registered URI for the cascade that cancels them
when it is removed (migration 29). Every realm's `account`,
`account-console` and `security-admin-console` now have the reference's
root, base and redirect URLs, so `account-console` signs in.
`tests/public/redirect_matching_contract.py` checks 4 groups, the slowest
in 215 ms, including an `account-console` sign-in.

Remaining differences (post-logout matching came later, see below): origins are not
derived from relative redirect URIs; `security-admin-console` has no
`webOrigins` (`+` is not supported) and no console is served at its URL;
relative URIs require a `rootUrl`, which the reference may not require.

## Post-logout redirect matching

RP-initiated logout now matches `post_logout_redirect_uri` with the same
function as login redirects, against the client's post-logout URIs plus,
with `+`, its redirect URIs, following the 6 recorded cases in
`tests/reference/logout-redirect-observations.json`. Registered post-logout
URIs may now end in `/*`. `tests/public/logout_redirects_contract.py`
checks one case per test, the slowest in 245 ms.

## User search

`GET /users` and `/users/count` accept `search`, `username`, `email`,
`firstName`, `lastName`, `enabled`, `emailVerified` and `exact`, following
the 26 recorded cases in `tests/reference/user-search-observations.json`.
`search` is a case-insensitive prefix over username, email and names (`*`
a wildcard, quotes for exact) and replaces `username`; the field filters
match infix or, with `exact=true`, exactly; all combine with AND. The
handler turns each parameter into an escaped lowercase `LIKE` pattern, so
`%` and `_` in values are literal, and one storage condition serves both
listing and counting. `briefRepresentation=true` drops the credential and
action fields. `tests/public/user_search_contract.py` checks 4 groups, the
slowest in 285 ms.

Remaining differences: the brief form has no `access` map; first and last
name filters use `lower()` without an index, which large realms will need.

## Role updates and roles by id

`PUT /roles/{name}` and the client role form replace a role's name and
description, and `/roles-by-id/{id}` reads, updates, edits composites and
deletes any role of the realm, following the 22 recorded cases in
`tests/reference/role-update-observations.json`. The by-id routes resolve
the role and then run the name-based handlers with the role's own
container, so client roles keep needing client access; they require a valid
admin token for the realm before saying whether an id exists. Updates accept
the read-only fields admin clients send back (`id`, `composite`,
`clientRole`, `containerId`, empty `attributes`). Role creation and update
share one name and description parser. `tests/public/role_updates_contract.py`
checks 5 groups, the slowest in 372 ms.

Remaining differences: renaming the default role is allowed, a case the
reference was not recorded for; role attributes stay unsupported.

## Group renames and moves

`PUT /groups/{id}` renames a group and posting an existing group's `id` to
a parent's `/children` or to `/groups` moves it, following
`tests/reference/group-update-observations.json`. Name conflicts among the
destination's siblings, top level included, answer 409 "Sibling group named
'…' already exists."; subgroup paths follow because they are computed from
names. Updates accept the read-only fields admin consoles send back.
`tests/public/group_updates_contract.py` checks 3 groups, the slowest in
268 ms.

Remaining differences: names with `/` stay refused, since they make paths
ambiguous, where the reference accepts them on rename; moving a group under
its own subgroup answers 400 "Cannot move a group into its own subgroup"
where the reference fails with a 500; moving a group into itself is a 204
no-op, as recorded; group attributes stay unsupported.

## Admin session management

`/users/{id}/sessions`, `POST /users/{id}/logout`, `DELETE /sessions/{id}`,
`/clients/{id}/user-sessions` (with `first` and `max`),
`/clients/{id}/session-count`, `/client-session-stats` and
`POST /logout-all` follow the 15 recorded cases in
`tests/reference/admin-session-observations.json`. Ending a session revokes
its refresh families, so every client's refresh tokens stop working while
other sessions continue. A session's `lastAccess` is its latest start or
token refresh; each change is audited. The test fixture gained
`browser_session` and `sso_login` for signing a second client into the same
session. `tests/public/admin_sessions_contract.py` checks 5 groups, the
slowest in 403 ms.

Remaining differences: sessions have no `ipAddress`, since client addresses
are not stored; offline sessions are not modelled, so `offline` counts are
"0"; `logout-all` does not push a not-before time to clients.

## Realm display name and token lifespan

Realms store `displayName` and `accessTokenLifespan` (migration 30),
following `tests/reference/realm-setting-observations.json`. The lifespan,
300 seconds by default, now sets `expires_in` and the access and ID token
lifetimes of the code, refresh and client-credentials grants, read once per
token request. The login page names the realm by its display name. Realm
updates now take a `RealmChanges` value instead of one argument per field.
`tests/public/realm_settings_contract.py` checks 4 groups, the slowest in
270 ms.

Remaining differences: zero and negative lifespans answer 400, where the
reference stores them; `displayNameHtml`, `accessTokenLifespanForImplicitFlow`
and the SSO session timeouts (fixed at 1800 seconds here, against the
reference's 1800 idle and 36000 maximum) are not settable.

## Realm keys

`GET /admin/realms/{realm}/keys` lists the active key by algorithm and the
key itself, following `tests/reference/realm-key-observations.json`. Every
realm signs with the one operator-provided RS256 key, so the listing has
that key alone, with its JWKS `kid` and its public key as base64 DER
SubjectPublicKeyInfo, built with the `spki` crate already in the
dependency tree. `tests/public/realm_keys_contract.py` checks the key
against the realm's JWKS in 85 ms.

Remaining differences: there is no certificate, key provider component,
`validTo`, or HS512, AES and RSA-OAEP keys, and realms cannot have keys of
their own.

## Required action administration

`/authentication/required-actions` lists, reads and updates the four
required actions this server performs, following
`tests/reference/required-action-admin-observations.json`. Realms keep only
changed actions (migration 31). `rs_active_required_actions` filters a
user's assigned actions by the realm's settings, and every place that
decides whether a session waits for steps, or which step comes next, uses
it, so a disabled action is skipped at login while users keep it assigned.
Default actions are added to users created through the admin API.
`tests/public/required_actions_admin_contract.py` checks 4 groups, the
slowest in 310 ms.

Remaining differences: the other ten reference actions (terms and
conditions, WebAuthn, recovery codes and more) are not listed; priorities
cannot be changed, so the login order stays fixed.

## Default client scopes and user claims

Code-flow logins accept `openid`, `profile` and `email`, grant the
reference's default `email` and `profile` scopes whatever is requested,
and redirect any other scope back as `invalid_scope`, following
`tests/reference/default-scope-observations.json`. Access tokens, ID tokens
and userinfo carry `preferred_username`, `name`, `given_name` and
`family_name` for `profile`, and `email` and `email_verified` for `email`,
through one `UserClaims` value flattened into both token types and built
from the user once per token request. A grant without `openid` gets no ID
token, and its userinfo answers 403 as before. Refresh requests may name
these scopes, but refreshed tokens keep the family's scope, so a request
cannot widen it. Service-account tokens are unchanged.
`tests/public/default_scopes_contract.py` checks 5 groups, including a
refresh, the slowest in 257 ms; the crypto test now also checks the
flattened claims and the admin keys' SubjectPublicKeyInfo.

Remaining differences: client scopes cannot be listed, created or
assigned, so every client has exactly these defaults; access tokens lack
`acr`, `allowed-origins` and `auth_time`, and ID tokens `acr`, `at_hash` and
`jti`; refresh does not narrow the scope to the request.

## Faster checks

`tests/public/fast.py [--workers N] BINARY [CONTRACT ...]` runs the contract
files in parallel against one migrated database (two workers by default),
prints the slowest tests, and fails if any test takes more than 500 ms.
Without names it runs every contract except the Docker-backed `oidc` and
`cors` contracts and `bootstrap`, which needs a fresh database and stays in
`database.sh`. Against the release binary the whole set takes about 14
seconds with three workers, the slowest test near 300 ms; the debug binary
takes about twice as long per request, so parallel debug runs can push the
heaviest tests past the limit. The runner takes `--workers` as an option
because the server refuses unknown `RS_KEYCLOAK_` variables, which the
contract servers would inherit.

`tests/reference/batch.py` records and compares several reference baselines
against one start of the pinned Keycloak, described in
`tests/reference/README.md`.

## Client scope listings

`/client-scopes`, `/client-scopes/{id}`, the realm's default and optional
scope lists and each client's default and optional scopes are served
read-only, following `tests/reference/client-scope-observations.json`, and
client representations list `defaultClientScopes`. Only the scopes this
server performs are listed, `basic`, `email`, `profile` and `roles`, as
every client's defaults; their ids are version 8 UUIDs derived from the
realm and the name, so they are stable without storage.
`tests/public/client_scopes_contract.py` checks 2 groups.

Remaining differences: scopes cannot be created, edited or assigned and
have no protocol mappers; `acr`, `web-origins` and the optional scopes
(`offline_access`, `address`, `phone` and others) are missing, as are the
SAML scopes.

## Offline access

Logins may request `offline_access`, following
`tests/reference/offline-access-observations.json`. The refresh family is
then offline (migration 32): its 30-day lifetime does not follow the login
session, logout and admin sign-out leave it, and its refresh tokens are
typed `Offline`. Revocation ends only the offline family, and removing the
user's consent for the client ends its offline families too, both then
answering "Offline user session not found". Access tokens refreshed from a
live offline family stay valid after the login session ends. Admins list
offline sessions per user and client and per client, count them, and see
them in `client-session-stats`. A user without the `offline_access` role
gets `not_allowed` at the code exchange, as Keycloak answers (not recorded).
Clients without post-logout URIs now accept their redirect URIs at logout,
as the reference does. `tests/public/offline_access_contract.py` checks 5
groups.

Remaining differences: the online session of an offline login stays listed
under `/users/{id}/sessions`, where the reference lists none; introspection
reports offline refresh tokens as `Refresh` and only while their login
session lives; offline sessions have no idle timeout; a refused
`not_allowed` exchange still leaves an unused offline family.

## Account console API routes

`/account/applications`, `/account/sessions/devices`, `DELETE
/account/sessions` and `DELETE /account/applications/{clientId}/consent`
follow `tests/reference/account-console-api-observations.json`.
Applications are the clients of the caller's current session (`inUse`), and
those the user has consented to or holds offline tokens for, with
`effectiveUrl` resolved from the client's root and base URLs. Ending the
other sessions also ends their offline tokens, as recorded; the
password-update "sign out other devices" box keeps them, since that case was
not recorded. Removing an application's grant reuses consent revocation,
offline tokens included. `tests/public/account_console_api_contract.py`
checks 3 groups.

Remaining differences: user agents and addresses are not recorded, so all
sessions belong to one unknown device without `ipAddress` or browser.
`clientName` and `description` now come from the client (see "Realm and
client settings in the account console"). The console itself is described
in "Account console" below.

## Realm partial export

`POST /admin/realms/{realm}/partial-export` follows
`tests/reference/partial-export-observations.json`: the realm with its
client scopes, required actions and default role; `exportGroupsAndRoles`
adds realm roles and the group tree with role mappings, plus client roles
when clients are exported too; `exportClients` adds every client, secrets
masked as `**********` without being opened, and the service-account users.
Regular users are never exported. The export reuses the admin
representations, so it shows exactly what the admin API does. Access needs
`view-realm`, plus `view-users` for groups and roles and `view-clients`
for clients. `tests/public/partial_export_contract.py` checks 5 groups.

Remaining differences: the realm representation still has a small subset
of the reference's fields and no `components`.

## Realm partial import

`POST /admin/realms/{realm}/partialImport` imports realm roles, clients and
users with `ifResourceExists` `FAIL`, `SKIP` or `OVERWRITE`, following
`tests/reference/partial-import-observations.json`, and answers the added,
skipped and overwritten counts with one result per resource. Every
resource is looked up before anything is written, so a `FAIL` conflict
changes nothing. Clients and users go through the same create and update
functions as their admin routes, now shared, so imports accept and refuse
exactly what the API does. `tests/public/partial_import_contract.py` checks
4 groups.

Client roles, the group tree with realm and client role mappings, and
users' role mappings and group memberships by path import too, following
`tests/reference/partial-import-group-observations.json`, in the order
realm roles, clients, client roles, groups, users, so later resources can
name earlier ones; `tests/public/partial_import_groups_contract.py` checks
them.

Remaining differences: groups need no path here, where the reference fails
with a 500 without one; an overwrite of a group adds missing subgroups and
mappings but removes nothing; an overwrite does not also count the role as added; imported users get the
default role, like every user created here; malformed JSON answers 400
rather than 500; resources are written one by one, so a failure part-way
through `SKIP` or `OVERWRITE` keeps what was already written; an export
cannot be imported as is, since it carries fields the admin API refuses.

## User creation with credentials

User creation, through the admin API and partial import, accepts
`credentials` with a password, following
`tests/reference/user-credential-create-observations.json`: `temporary`
defaults to false and adds `UPDATE_PASSWORD` when true, the last of several
passwords wins, and any other credential type refuses the creation with
400 "Could not create user". The password is hashed before the user is
written, and user and credential are stored in one transaction. Password
parsing and hashing are shared with password reset.
`tests/public/user_credentials_create_contract.py` checks 5 groups.

Remaining differences: an empty password is refused with 400, where the
reference stores a password credential without data; hashed or OTP
credentials cannot be imported.

## Account console

The optional `RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR` setting names a directory
that `compatibility/extract_account_console.py` fills from the pinned
distribution: `account/` (the keycloak.v3 theme), `account-base/` (the base
theme it extends) and `common/` (vendor modules). The server reads the
build manifest, theme locales and every locale's messages once at startup
and refuses to start if the directory is unusable. Everything follows
`tests/reference/account-console-observations.json`:

- `/realms/{realm}/account/` and every path below it render the reference's
  `index.ftl` output byte for byte, with the environment block filled from
  the issuer, the realm, `referrer`/`referrer_uri` (checked against the
  client's redirect URIs, else its base URL) and `scope`. A signed-in
  visitor's `KEYCLOAK_IDENTITY` enables applications, groups (when the user
  has any) and account deletion (when `delete_account` is enabled), from the
  account roles the `account-console` scope can carry. `index.html`
  redirects one level up, as recorded.
- Account routes dispatch as in the reference: a GET without an
  `application/json` Accept entry or content type gets the page, so
  `/account/applications` in a browser is the console, while the console's
  own calls reach the API. `/account/` with JSON is the profile, and
  `/account/supportedLocales`, `/account/linked-accounts` and
  `/account/groups` are new. Profile metadata now has the reference's
  validators, annotations and user-metadata group, and API answers say
  `application/json;charset=UTF-8`.
- `/resources/{version}/account|common/{theme}/{path}` serves files with the
  reference's types and `no-cache`. Files under `assets/` carry a content
  hash: any well-formed version serves them, with the current version as
  ETag and 304 on a match. Other files under another version redirect (307)
  to the current one. Encoded, dot-segment and unknown paths answer 404.
  The version is five `[0-9a-z]` characters derived from the server version.
- `/resources/{realm}/account/{locale}` lists messages: English, then the
  language, then the full tag, base theme before keycloak.v3, plus
  `locale_<tag>` display names. Locales resolve against the theme's list
  (exact tag, then first of the same language, else `en`), and `zh-CN` and
  `zh-TW` read the `zh_Hans` and `zh_Hant` files, which reproduces all 43
  recorded bundles. Display names come from the JDK in the reference, so
  the recorded values are embedded. Any origin may read them, with
  credentials; `?source=true` adds `"source": "THEME"`.
- The iframes keycloak-js loads, `3p-cookies/step1.html`, `step2.html` and
  `login-status-iframe.html` with its `/init` origin check, serve the
  reference's pages with its caching rules. `KEYCLOAK_SESSION` now holds the
  base64url SHA-384 of the session ID, which the login status iframe
  compares with `session_state`; before, the iframe would have reported
  every session as changed.
- These routes send the reference's security headers (`security_headers`
  module); other routes are unchanged.

`tests/public/account_console_contract.py` checks 13 groups, the slowest in
268 ms; console cases fail unless `RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR` is set,
and `tests/public/database.sh` refuses to start without it. Without the
setting, the server's console routes answer 404 and account routes stay
JSON only.

Remaining differences: the signed-in page does not re-issue the SSO cookies; `/account/groups` has only the brief
form; login, admin and email theme resources and messages are not served;
names and scopes are JSON-escaped in the page, where the reference inserts
them as they are; the token response still has no `session_state`.

## Realm and client settings in the account console

Clients now store `name` and `description`, and realms store
`internationalizationEnabled`, `supportedLocales`, `defaultLocale`,
`editUsernameAllowed` and `registrationEmailAsUsername` (migration 33).
Everything follows `tests/reference/account-settings-observations.json`:

- The admin API accepts and returns them as recorded: absent and null keep
  a value, an empty name, description or default locale is stored as
  given, numbers become text in names, empty locale lists are left out of
  the representation, and values of the wrong JSON type answer "Cannot
  parse the JSON". Built-in clients are named `${client_<clientId>}`.
  Partial import leaves the realm settings alone, as for the others.
- The console's referrer name and `/account/applications` use the client
  name, with the client ID when it is blank, and the description.
- The page locale follows the `locale` module, a port of the pinned
  `DefaultLocaleSelectorProvider`: English unless internationalization is
  on, else the user's locale, the `KEYCLOAK_LOCALE` cookie, then
  `Accept-Language` by quality, each matched by language and region, then
  the default locale, then English. `dir` is `rtl` when the locale's display
  name in the theme has right-to-left characters, as the reference's
  `Bidi` check decides, so `ar` and `fa` are `rtl` and `he`, which the theme
  does not name, is `ltr`. The page features show the three realm flags.
- `/account/supportedLocales` lists the stored locales, also while
  internationalization is off.
- The account profile follows the realm's username rules: the username is
  writable only with `editUsernameAllowed` and without
  `registrationEmailAsUsername`, required unless the email is the username,
  and the email is read-only when it is the username and usernames may not
  change; a read-only email keeps its value. Updates report the
  reference's error lists, including read-only, missing and taken
  usernames, emails taken as emails or usernames, with 409 when anything
  collides. With internationalization on, the profile carries the `locale`
  attribute and its metadata, and updates store or remove it. Admin user
  creation takes the email as username when the realm says so.

`tests/public/account_settings_contract.py` checks 46 groups, the slowest
in 189 ms.

Remaining differences: supported locales are stored and listed sorted,
where the reference lists them in its Java hash set's order, and among
several locales that match a request equally the first sorted one wins;
`Accept-Language` entries with quality zero are left out, which was not
recorded; an update that leaves out `attributes` removes the user's locale,
which was not recorded either; the admin user representation does not show
the locale attribute; the theme's own page texts stay English, as in the
reference. Admin user updates and the login flow's profile update follow
the username rules since "Realm settings in the login flow".

## Realm settings in the login flow

The login flow follows realm internationalization and the username
settings, as recorded in `tests/reference/login-settings-observations.json`
and read from the pinned source (`DefaultLocaleSelectorProvider`,
`LocaleUtil`, `UpdateUserLocaleAction`, `DefaultLocaleUpdaterProvider`,
`LocaleBean` and the user profile's username and email conditions):

- Login, required-action, consent and forgot-password pages choose their
  locale from the `kc_locale` pick, the user's locale once the password is
  checked, the client's `ui_locales` (its first supported tag), the
  `KEYCLOAK_LOCALE` cookie, `Accept-Language`, the default locale, then
  English. `html` carries `lang`, and `dir` only while internationalization
  is on, decided as for the account console. Migration 34 keeps
  `ui_locales` and the pick with the authorization request.
- `kc_locale` counts on login-actions posts only (the password form and
  required actions), as in the reference, where the authorization endpoint
  reads it only for registration. With internationalization on, the pick is
  kept for the request and sets
  `KEYCLOAK_LOCALE=<tag>;Version=1;Path=/realms/<realm>/;Secure;HttpOnly;SameSite=None`.
- Once the user is known, every login step does what the reference's
  locale required action does: a pick that differs from the user's locale
  becomes theirs and is remembered; else the user's locale is remembered;
  else a sent cookie is removed with `Max-Age=0`. This also runs while
  internationalization is off, as in the reference.
- UPDATE_PROFILE shows the username only with `editUsernameAllowed` and
  without `registrationEmailAsUsername`, and the email unless it is the
  username and usernames may not change. A changed username the form does
  not show re-renders the form without a message, as the reference reports
  it on the hidden field; when the email is the username, the username
  follows the email. Messages use the reference texts, each field's format
  error first, then collisions with other users' usernames and emails.
- Admin user updates rename users only with `editUsernameAllowed`, and
  with `registrationEmailAsUsername` take the email as username and ignore
  a sent one. As the reference does, every error is collected, then the
  first missing username, taken username or taken email answers, else the
  field errors with `params`, one alone or several in an `errors` list. An
  email that is another user's username counts as taken.

`tests/public/login_settings_contract.py` checks 59 groups, the slowest in
192 ms.

Remaining differences: the reference reaches required actions through a
redirect and sets the locale cookie on each hop, where this server answers
with the page, so the contract compares an exchange's locale cookies as a
set; `kc_locale` values other than letters, digits, `-` and `_` are
ignored, where the reference keeps them as sent; `kc_locale` on the SSO
path and logout is not implemented. Page texts and language links came
later, see "Login page texts".

## Login page texts

The login, OTP, CONFIGURE_TOTP, UPDATE_PASSWORD, UPDATE_PROFILE,
VERIFY_EMAIL, consent and forgot-password pages show their titles,
headings, labels, buttons, links, messages and field errors from the pinned
login theme, as recorded in `tests/reference/login-message-observations.json`
and read from the pinned source (`DefaultThemeManager`, `FileBasedTheme`,
`LocaleUtil`, `LocaleBean`, `MessageFormatterMethod`, the keycloak.v2
templates):

- The base login theme's 41 bundles are embedded from
  `crates/http/src/login_theme`, extracted by
  `compatibility/extract_login_messages.py` from the pinned distribution;
  the keycloak.v2 theme on top only adds theme descriptions.
- A page reads its locale's bundles, then its parents': a region falls
  back to its language, a language to the realm's default locale, and that
  to English, unless the default has the page's language. Each locale
  reads its JDK bundle name, and `zh-CN` and `zh-TW` also `zh_Hans` and
  `zh_Hant`. Values are Java `MessageFormat` patterns, with `''` quotes
  and `{n}` arguments; a missing key shows as itself.
- With internationalization on and more than one supported locale, the
  page lists the realm's locales as links, the current one marked, labelled
  as the theme generates them (the JDK's name in the page's language, then
  the locale's own name) or by the tag outside the theme's locales, and
  sorted ignoring accents and case. A link re-shows the page through
  `login-actions/authenticate/{request}?kc_locale=<tag>` (the
  forgot-password form through its own URL), which keeps the pick and sets
  the cookie; once the password is checked, that URL shows the session's
  next step. `dir` now follows the same label.
- Pages carry the reference's messages: the required action's reminder,
  `invalidUserMessage` on the username field, `emailSentMessage`, TOTP's
  `missingTotpMessage` and `invalidTotpMessage`, the password's
  `missingPasswordMessage` and `notMatchPasswordMessage`, and the profile's
  `error-user-attribute-required`, with `missingEmailMessage` before it for
  an empty email. An empty forgot-password request shows the form again
  with `missingUsernameMessage`; the login page after a sent one ignores
  the `kc_locale` pick, as the reference shows it from a fork of the
  login. The emailed link's new-password form is the same form with
  `resetPasswordMessage`, in the login's locale when this browser started
  it, else the realm's; there it makes the kept pick the user's locale,
  and its language links keep the key, as the reference forwards it. The
  OTP page shows the username
  and leaves the locale cookie and user locale alone, since the reference
  runs its locale action after authentication.

`tests/public/login_messages_contract.py` checks 21 groups, the slowest in
under 300 ms.

Remaining differences: the language links name `authenticate`, where the
reference names each step's login-actions path, so links are compared by
label, selection and locale; a page in a locale outside the theme whose
language the theme lacks (such as `eo`) takes its language labels from its
fallback locale, where the reference asks the JDK, and the order can
differ for scripts the JDK's collator orders otherwise; themes other than
the pinned default are not implemented (realm localization texts, email
login and the TOTP QR code came later, see "Realm localization texts",
"Email login and duplicate emails" and "TOTP setup QR code"); a
login continued from the page after a sent email
keeps the pick, where the reference's fork has none. Info, error and
logout pages are in "Info and error pages".

## Info and error pages

The pages an emailed link opens outside its login, and the error pages of
refused authorizations, show the pinned theme's `info.ftl` and
`error.ftl` texts, as recorded in
`tests/reference/login-info-page-observations.json` and read from the
pinned source (`ExecuteActionsActionTokenHandler`,
`VerifyEmailActionTokenHandler`, `LoginActionsService.handleActionToken`
and `detachedInfo`, `DetachedInfoStateChecker`, `MessageFormatterMethod`):

- An admin-sent link lists its actions under `confirmExecutionOfActions`
  with a `proceedWithAction` link; its pages read a `kc_locale` pick, then
  the user's locale, the cookie, `Accept-Language` and the realm default.
  The reference keeps the pick in the authentication session the link
  starts in this browser; here the page's onward links carry it in
  `picked_locale`, so another browser does not see it. The password form
  then runs the locale action, which makes the pick the user's locale, and
  ends on `accountUpdatedTitle` and `accountUpdatedMessage`.
- A verification link shows `confirmEmailAddressVerification`, then
  verifies and ends on the same account-updated page; an already verified
  address shows `emailVerifiedAlreadyMessage` with a back link. Their
  headings use the locale without the user's own, as the reference formats
  them before it knows the user, and are read again as a message pattern,
  as `info.ftl` passes them to `msg`, so French `l''adresse` shows as
  `ladresse`.
- A used or expired key shows `expiredActionMessage` with a link back to
  the account console; a key never issued shows `invalidCodeMessage`. An
  unknown client, a bearer-only client and an unregistered redirect URI
  of an authorization show `clientNotFoundMessage`, `bearerOnlyMessage`
  (403) and `invalidParameterMessage`. These pages skip the user's locale
  and the client's `ui_locales`, as the reference shows them before a
  login exists.
- Browser logout follows `LogoutEndpoint.logout`: a hint whose client
  exists, or a `client_id` that matches the hint, or a registered redirect
  with no session in the browser, skips the confirmation; an unknown
  `client_id`, or a browser session other than the hint's, forces it. The
  confirmation (`logoutConfirmTitle`, `logoutConfirmHeader`, `doLogout`)
  is kept in a new `logout_requests` row bound to an `rs_logout` CSRF
  cookie, as the reference keeps a logout authentication session; its
  language links re-show it through `GET logout/logout-confirm`, which
  keeps the pick, and its form posts there. The logout ends the hint's
  session and the SSO cookie's, then redirects or shows `successLogout`
  in the pick, the user's locale, then `ui_locales`. Refused logouts show
  `missingParameterMessage`, `invalidParameterMessage` (also for a
  `client_id` other than the hint's, as the source names `id_token_hint`
  there) and `invalidRedirectUriMessage`; a confirmation no longer kept
  shows `failedLogout` while a session remains, else `successLogout`.
  Logout pages are `no-cache`, as recorded.
- TOTP setup keeps its key for the rest of a login, through language
  links and failed codes, as the reference keeps it in the
  authentication session: the first key drawn is sealed with the server's
  secret key, bound to the request, in a new `totp_setup_secret` column of
  the authorization request. A new authorization draws a new key, as
  recorded.
- Pages without a login to re-show them from link their languages to
  `login-actions/detached-info` with a fresh `kc_state_checker`, and set
  the `KC_STATE_CHECKER` cookie (path of the realm, 300 seconds, strict)
  that holds the message, as the reference does. The cookie is sealed with
  an HMAC key derived by HKDF from the signing key, where the reference
  signs it with the realm's HMAC key, so every instance with the same
  signing key accepts it. A state that matches neither the cookie's
  current nor rendered state shows `expiredActionTokenNoSessionMessage`.

`tests/public/login_info_pages_contract.py` checks these pages, each test
under 200 ms.

Remaining differences: the logout confirmation has no back link, as this
server keeps no client base URL; the detached page keeps a back link as a URL,
where the reference keeps the client and re-checks it; the action list
offers only UPDATE_PASSWORD, as before; a key past its lifespan shows
`expiredActionMessage`, where the reference's expiry check shows
`expiredActionTokenNoSessionMessage`, and once its row is purged it reads
as never issued.

## Realm localization texts

Realms keep localization texts per locale, managed through the admin
`/localization` endpoints and shown on login pages over the theme's
messages, as recorded in
`tests/reference/realm-localization-observations.json` and read from the
pinned source (`RealmLocalizationResource`, `JpaRealmProvider` and the JPA
`RealmAdapter`, `LocaleUtil.enhancePropertiesWithRealmLocalizationTexts`,
`MessageFormatterMethod`, `TemplatingUtil`):

- A new `realm_localizations` table (migration 37) holds each locale's
  texts as one JSON object, as `REALM_LOCALIZATIONS` does, so a locale
  saved with no texts, or whose last text was removed, stays listed.
- `GET localization` lists the locales sorted; `GET {locale}` returns its
  texts, `{}` for an unknown locale, over the default locale's with the
  deprecated `useRealmDefaultLocaleFallback=true`; `GET {locale}/{key}`
  returns the text as `text/plain`. These need any `realm-management`
  role.
- `PUT {locale}/{key}` takes a `text/plain` body (else 415); `POST
  {locale}` merges a JSON object, or the JSON `file` part of a form upload,
  into the locale's texts, numbers and booleans becoming texts as Jackson
  coerces them; `DELETE {locale}` and `DELETE {locale}/{key}` remove them.
  These need `manage-realm` and write an audit event. Errors carry the
  reference's `error` bodies.
- `localizationTexts` given at realm creation are saved; realm updates
  ignore them and the realm representation leaves them out, as in the
  reference. Partial export always carries them, and partial import
  ignores them.
- A page's messages read, for each locale of its fallback chain, the
  realm's texts of that locale before the theme's bundles, so a realm text
  wins over the theme's text of its locale and loses to a theme text of a
  more specific locale. Texts are message patterns, and `${key}` in a
  message is replaced by that key's message; arguments, such as the realm
  display name in the title, are not, as recorded. Language labels read
  `locale_<tag>` texts the same way. Pages outside a realm stay English.

`tests/public/realm_localization_contract.py` checks 6 groups, each under
100 ms.

Remaining differences: `rememberMe` is not implemented, so the login
page's "Remember me" label is not compared; email templates do not read
realm texts yet; texts are read from the database for each page, where the
reference caches the realm.

## Email login and duplicate emails

Realms keep `loginWithEmailAllowed` (on by default) and
`duplicateEmailsAllowed` (off), as recorded in
`tests/reference/login-email-observations.json` and read from the pinned
source (`KeycloakModelUtils.findUserByNameOrEmail`,
`AbstractUsernameFormAuthenticator`, `ResetCredentialChooseUser`,
`DuplicateUsernameValidator`, `DuplicateEmailValidator`,
`UserResource.validateUserProfile` and the JPA `RealmAdapter` and
`JpaUserProvider`):

- Migration 38 adds both settings. The realm representation shows them,
  and creation and updates apply them as the reference's setters do, in
  its order: email as username, then email login, which turns duplicates
  off, then duplicates, which turn email login and email as username off.
- The login, OTP and forgot-password forms label the field `username`
  without email login, else `email` with email as username, else
  `usernameOrEmail`.
- Sign-in with an input holding '@' looks the email up first while email
  login is allowed, then the username. An email several users share shows
  `usernameExistsMessage` on the login form, as the reference's lookup
  refuses it. Forgot-password looks up the username first, then such an
  email.
- Users keep an `email_unique` flag, as the reference keeps
  `EMAIL_CONSTRAINT`: an email set while the realm allows duplicates is
  not unique, others are, and the unique index covers only unique ones.
  Users made while duplicates were allowed keep their shared email after
  they are turned off.
- Admin user creation now checks a missing username, then a taken
  username, then a taken email before the field errors, as the reference
  does. A username with '@' after its first character that is another
  user's email is taken while email login is allowed; a changed email is
  checked only without duplicates, against other users' emails and, with
  email login, usernames; an email lookup that finds several users answers
  409 `User exists with same username or email`. UPDATE_PROFILE and the
  account console follow the same email rules.

`tests/public/login_email_contract.py` checks 15 groups, each under
250 ms.

Remaining differences: users without a name or email are not sent to
VERIFY_PROFILE, so the two recorded sign-ins that end there are not
replayed; a forgot-password request naming a shared email sends no mail,
where the reference's lookup fails; the reference turns an email made
unique again (after duplicates end) back into a constraint on lookup,
which this server does not.

## TOTP setup QR code

The CONFIGURE_TOTP page shows the reference's QR code and manual mode, as
recorded in `tests/reference/totp-qr-observations.json` and read from the
pinned source (`TotpUtils`, `QRCodeUtils`, `OTPPolicy.getKeyURI`,
`TotpBean`, `login-config-totp.ftl` and `qr-code.ftl` of keycloak.v2):

- The code holds the key URI
  `otpauth://totp/<issuer>:<account>?secret=…&digits=6&algorithm=SHA1&issuer=<issuer>&period=30`.
  The issuer is the display name with `${key}` resolved in the page's
  messages, so realm texts in the user's locale name it, else the realm
  name; ':' becomes a space, and both parts are encoded as Java's
  `URLEncoder` does, the issuer with `%20` for spaces.
- The code is drawn as zxing's `QRCodeWriter` draws it: error correction
  level L without raising it, one segment, a four-module quiet zone,
  scaled by a whole number into 246 pixels and centered, written as a
  one-bit grayscale PNG in a `data:` URL. It uses the pinned `qrcodegen`
  1.8.0 (MIT) and `png` 0.18.1 (MIT or Apache-2.0) crates.
- "Unable to scan?" opens the manual mode through
  `login-actions/required-action?execution=CONFIGURE_TOTP&mode=manual`,
  which shows the key in groups of four with the policy, and "Scan
  barcode?" returns with `mode=qr`. The form keeps a chosen mode in a
  hidden `mode` field, so a failed code re-shows the same mode; the key
  stays the same throughout, as before. The page no longer shows the key
  URI as text.
- `tests/qr_code.py` reads a code from its PNG with the standard library
  and checks its Reed-Solomon bytes, so the recorder and contract compare
  codes by content, size, quiet zone, version and level; it was checked
  against the pinned distribution's zxing 3.4.0 jars.

`tests/public/totp_qr_contract.py` checks 5 groups, each under 150 ms, and
`tests/public/login_messages_contract.py` now compares the TOTP page's
list items and links too.

Remaining differences: the QR code's mask can differ from zxing's, which
the comparison by content does not see; HOTP policies and other OTP
policy settings are not implemented, so the policy shown is the default.
