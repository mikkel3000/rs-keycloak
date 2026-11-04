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

Remaining differences: new realms have no built-in clients (`account`,
`admin-cli`, `broker` and others), so unfiltered lists are shorter; the
representation lists only the 13 modelled settings of the reference's 26
fields; direct access, implicit, bearer-only, non-OIDC protocols, other
authenticators, attributes other than S256 PKCE, and client updates are
refused or missing; the CLI cannot rotate a sealed secret.

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

Remaining differences: composite editing, role attributes and client roles
are refused; deleting the default role answers 400, a response the reference
was not recorded for; `resource_access` and roles inherited from groups are
not yet in tokens; admin authorization still checks only the master `admin`
role.

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

Remaining differences: there is no SSO cookie yet, so browser logout without
`id_token_hint` has no session to end and shows a plain page instead of
Keycloak's confirmation form; front-channel and back-channel logout
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
