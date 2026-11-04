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
still returns 403, where the reference allows all origins and answers
"Client not found".
