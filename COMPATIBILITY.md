# HTTP API compatibility contract

## Baseline

Use Keycloak `26.8.1` as the initial reference, checked on 2026-11-01 against the [release page](https://www.keycloak.org/downloads) and [tagged feature source](https://github.com/keycloak/keycloak/blob/26.8.1/common/src/main/java/org/keycloak/common/Profile.java).

This is a bounded version contract, not a promise to match every Keycloak release; changing the target requires a reviewed contract diff and new test evidence.

The product must replace a maintained Keycloak deployment after verified migration: compatibility covers HTTP paths/methods, schemas, status codes, headers, redirects, cookies, auth rules and resulting state, including OIDC, SAML, Admin/Account APIs, Authorization Services, federation, organizations, SCIM, workflows and Rust alternatives for custom login/policy/mapping behavior.

HTTP compatibility does not require a Java runtime, Java extension ABI, identical HTML/CSS or an identical internal schema; full feature coverage still requires working login, account and admin workflows, not only matching response shapes.

Existing application integrations must work after cutover without adopting a new auth API; source-code ports, script-authoring automation changes, deprecated-feature changes and session re-login are migration requirements that must be reported before calling a deployment replaceable.

Before implementation, record the resolved source commit, reference image digest, exact feature versions, client library versions, and source hashes in `compatibility/reference.lock`; never run release tests against a moving `latest` tag.

The current documents are a plan, not a completed endpoint inventory or a claim of parity.

## Scope rules

1. Include all maintained, nondeprecated public HTTP APIs and their state changes, including supported features that upstream disables by default, subject to the explicit exclusions below.
2. Exclude legacy and deprecated behavior, as requested; use the pinned source, release notes, protocol security guidance, and observed behavior to classify each exclusion.
3. Check explicit deprecation flags and annotations as well as the feature type; a feature can be deprecated while its type is still `DEFAULT` or `PREVIEW`.
4. Preview and experimental public APIs are not automatically excluded: inventory and implement maintained API behavior in explicit opt-in profiles, with the same safety tests and maturity labels; script execution is replaced by Rust providers rather than dropping custom authentication, policy or mapper capabilities.
5. Match externally visible behavior rather than Keycloak's Java runtime, private classes, database layout, caches, or deployment tools.
6. Never mark a route complete because it accepts a request, stores opaque JSON, returns a canned response, or has a passing CRUD test; prove the feature's effect on authentication and permissions.
7. Refuse unsupported configuration and imports with field-specific errors; never silently drop policy, credentials, providers, or feature options.
8. A safety fix may differ from vulnerable reference behavior only through a recorded security exception with a regression test; ordinary differences block the compatibility claim.

Keycloak publishes separate supported, preview, and deprecated feature groups, but the [pinned feature source](https://github.com/keycloak/keycloak/blob/26.8.1/common/src/main/java/org/keycloak/common/Profile.java) must settle the exact version and deprecation state; preview features retain their upstream warning rather than becoming supported merely because they run in Rust. [Feature lifecycle](https://www.keycloak.org/server/features).

## Required API families

| Contract | Required behavior | Public proof |
| --- | --- | --- |
| OIDC and OAuth | Discovery, authorization code with PKCE, client credentials, refresh, userinfo, JWKS, introspection, revocation, standard logout, session checks, consent, scopes, protocol mappers and claims | Pinned clients complete flows and reject invalid, expired, replayed, or misbound input |
| Modern OAuth features | Device flow, CIBA, PAR, DPoP, standard token exchange v2, JWT grants, client assertions, client secret rotation, client policies and supported request/response modes | Grant lifecycle, polling, proof binding, audience limits, rotation and negative tests |
| SAML 2.0 | Metadata, supported bindings, signed/encrypted assertions, login, logout, client configuration, attribute mapping, step-up and broker flows | Independent SP/IdP clients plus signature, wrapping, replay and destination tests |
| Admin REST | Realms, clients, scopes, users, user profiles, groups, roles, composites, mappings, sessions, credentials, keys, events, policies, authentication flows, required actions, components, providers, import/export and server metadata | Every in-scope route/method, permission boundary, filter, pagination mode and side effect |
| Account and browser flows | Account REST, profile and credential changes, session management, consent, linked identities, registration, reset, verification, email changes, recovery and required actions | Browser journeys through pinned Admin and Account Console assets and `keycloak-js` |
| Authentication | Password policies, maintained credential algorithms, TOTP/HOTP, WebAuthn, passkeys, recovery codes, conditional flows, step-up, brute-force defense and impersonation | Real login plus race, lockout, recovery, cross-realm and privilege tests |
| Authorization Services | Resources, scopes, permissions, policies, decision strategies, UMA discovery, tickets, protection API, RPTs and permission evaluation | Independent policy enforcers exercise allow and deny decisions, including nested policies |
| Federation and brokering | Maintained OIDC/SAML/social brokers, LDAP/AD, Kerberos, mapper behavior, linking, synchronization, client trust providers and brokering API v2 | Test upstreams, real protocol exchanges, failure handling and account-linking attacks |
| Organizations and provisioning | Organization membership, domains, invitations, identity providers, claims, SCIM API and workflow lifecycle | Tenant boundaries, provisioning races, workflow retry/cancel behavior and policy effects |
| Other maintained APIs | Dynamic client registration, Docker Registry protocol, resource indicators, credentials/presentation APIs and other opt-in public features found in the pinned inventory | Per-profile protocol tests with explicit discovery and enable/disable behavior |
| Events and integrations | User/admin events, event filters, mail, logout callbacks, workflow jobs and current built-in provider behavior | Durable outcomes, redaction, retry behavior and delivery bounds |
| Custom behavior | Rust authenticators, authorization policies and OIDC/SAML mappers with migration bindings for supported provider configuration | Paired source/target flows preserve custom allow/deny decisions, challenges, claims and state changes |
| Deployment and lifecycle | Complete setup, multi-node operation, upgrades, backup/recovery and migration tooling | Fresh install and cutover using shipped docs; node loss and declared rolling upgrades preserve auth correctness |

The route inventory must combine the [Admin REST reference](https://www.keycloak.org/docs-api/latest/rest-api/index.html), [OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers), [Authorization Services guide](https://www.keycloak.org/docs/latest/authorization_services/index.html), and tagged server resources; Admin REST alone does not describe the whole server contract.

## Explicit exclusions

| Exclusion | Evidence or contract boundary | Replacement or handling |
| --- | --- | --- |
| Fine-grained admin permissions v1; login theme v1; login-failures v1; old logout-all-sessions behavior; multi-site v1; rolling-updates v1; conditional passkey authenticator v1; Instagram broker | Deprecated in the pinned feature source | Use maintained behavior; reject obsolete configuration |
| Token exchange v1; Twitter broker; identity-brokering API v1 | Explicit deprecated flag in the pinned source even where the feature type is not `DEPRECATED` | Standard token exchange v2 and brokering API v2; no Twitter provider substitute assumed |
| Resource-owner password/direct access grant; implicit token response flows | Legacy OAuth modes covered by the security BCP | Authorization code with PKCE or an appropriate modern grant |
| Legacy adapter-specific logout | Upstream labels the refresh-token logout format legacy | Standard OIDC/SAML logout and admin/account APIs |
| Removed adapters, obsolete endpoints and deprecated representation fields | Must have a tagged source or migration-guide citation in the final inventory | Reject requests or imports that require removed behavior |
| Execution of Java SPI/JAR binaries and the FreeMarker theme ABI | Non-Rust application backend/runtime interfaces | Port required custom behavior to Rust providers and themes to supported templates/branding before migration |
| Execution/authoring of Java-backed scripts and arbitrary JavaScript source | Rust-only backend; behavior must have a Rust alternative | Retain authenticator/policy/mapper capabilities through Rust providers; require a verified mapping before importing active script dependencies |
| Quarkus/JVM flags, Infinispan, Java-specific HTTP engines, SQLite, TiDB and other database backends | Implementation and deployment internals; user selected Rust and PostgreSQL | PostgreSQL is the only planned database; no database-portability layer or later PostgreSQL migration |
| Keycloak Operator/Quarkus deployment internals | Operational implementation outside the HTTP API contract | Own single-node and multi-node deployment templates, with tested failover and explicit upgrade compatibility |

The [tagged feature definitions](https://github.com/keycloak/keycloak/blob/26.8.1/common/src/main/java/org/keycloak/common/Profile.java) support the feature exclusions, the [OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html) covers unsafe grant modes, and the [OIDC guide](https://www.keycloak.org/securing-apps/oidc-layers) identifies the legacy logout format.

SAML, LDAP, Kerberos, offline sessions and Authorization Services stay in scope; age alone does not make a feature legacy.

Keycloak server scripts are JavaScript code with access to Java objects such as `KeycloakSession`, `RealmModel` and `UserModel`, sometimes through `Java.type`; they customize login decisions, authorization policies and token/SAML claims, and may be packaged in JARs. [Script provider API](https://www.keycloak.org/docs/latest/server_development/index.html#_script_providers).

Preserve these customization capabilities through built-in and custom Rust providers as defined in [RUST-PROVIDERS.md](RUST-PROVIDERS.md); ordinary browser JavaScript, `keycloak-js`, and the Admin/Account consoles remain in scope.

Provider metadata must describe the available Rust-backed capabilities accurately; compatibility bindings may preserve existing IDs/settings only for a verified behavior match, and imports with unmapped active code fail before mutation with a precise migration report.

Raw JavaScript upload and Java binary loading are explicit authoring exceptions, not a claim of unchanged code compatibility; preserve the surrounding HTTP resource lifecycle and application-visible behavior after mapping, and test that no API path can start a non-Rust backend runtime.

Protocol compatibility does not establish FIPS validation: a FIPS profile needs a validated crypto module, its required operating conditions, build evidence, and a separate qualification gate; the standard build must not advertise FIPS compliance. [Keycloak FIPS guide](https://www.keycloak.org/server/fips).

## Contract records and comparison

Create `compatibility/operations.json` with one row per route/method and relevant profile; each row records the source revision, lifecycle, request/response schema, permission, side effects, positive/negative/concurrency tests, implementation owner, and status.

Statuses are `planned`, `implemented`, `verified`, or `excluded`; exclusions require evidence and a reason, and the release report must count all in-scope rows so missing tests cannot look like success.

Record browser-only endpoints, feature dependencies, provider IDs and configuration schemas as well as published REST routes; track Rust replacements and code-authoring exceptions separately so runtime exclusions cannot hide missing customization capabilities.

Compare paired runs using equivalent synthetic realms and clients, with all input through public APIs, CLI import, or browser flows; do not seed private database tables to make compatibility tests pass.

Assert status codes, content types, headers, redirects, cookies, omitted versus null fields, unknown fields, error bodies, ordering where defined, defaults, filtering, pagination, IDs, permissions and state changes.

Normalize only specified nondeterminism such as generated IDs, timestamps and signatures; maintain ID relationships and verify signature validity, claim values and time bounds rather than masking whole tokens or responses.

Test unknown realms, disabled clients, revoked sessions, missing scopes, duplicate requests, malformed input, cross-realm IDs, encoding, unicode, proxy paths and feature-disabled requests; security-sensitive failures must not leak whether a user exists.

Run pinned `kcadm`, Java Admin Client, `keycloak-js`, generic OIDC clients, SAML clients and policy enforcers against rs-keycloak; use browser tests to expose gaps in account and console APIs that generated REST tests miss.

Use pinned upstream Admin and Account Console assets as the compatibility baseline with license notices and reproducible builds; Bun may build/serve the web interface, Rust implements all application APIs and login rendering, and native setup/provider screens must retain full in-scope workflow coverage.

Replace script-authoring controls with Rust provider selection/migration guidance and retain authenticator, policy and mapper management; disable only deprecated or impossible runtime actions with a clear reason, never an entire supported capability merely to make a browser test pass.

An upstream release update is a planned contract change: diff source, feature flags, deprecations and schemas, regenerate fixtures, run paired tests, review safety changes, and publish the compatibility report before updating the baseline.
