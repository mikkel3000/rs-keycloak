# Product opportunities and architecture review

Reviewed 2026-11-01 against [the plan](PLAN.md), [the HTTP API contract](COMPATIBILITY.md), and upstream documentation; the target is a complete replacement using PostgreSQL, Rust-only application logic, Rust alternatives to script capabilities, Bun web tooling and Google's Rust style guide.

The strongest product gains are predictable config changes, clear auth diagnostics, and safe operations; Rust and PostgreSQL can support those gains, but the language change alone does not provide them; additional product ideas below remain proposals.

## Highest-value opportunities

| Priority | Problem and evidence | Proposed rs-keycloak behavior | Proof needed |
| --- | --- | --- | --- |
| 1 | Startup import skips existing realms, while replacement import requires a stopped source/target workflow; import alone cannot reconcile desired config. [Import rules](https://www.keycloak.org/server/importExport) | Native `realm plan` and `realm apply`: validate config, show a redacted diff, detect drift, and apply a bounded change set against a known revision | A second apply makes no changes; stale plans fail; injected errors leave no partial config; unmanaged users and sessions survive |
| 2 | Auth spans flows, scopes, role mappings and policies; Keycloak already offers permission and token evaluation, so merely adding an evaluator is not a new gain. [Existing evaluation tools](https://www.keycloak.org/docs/latest/server_admin/index.html#_client_scopes_evaluate) | One protected explanation links a failed flow step, missing scope, mapper output or policy decision to its config revision and rule ID | An authorized operator can explain a missing claim or denied action without raw tokens or debug-level request dumps |
| 3 | Configuration has build-time and runtime phases; optimized startup rejects changed build options. [Configuration lifecycle](https://www.keycloak.org/server/configuration) | One runtime config schema, read-only validation, source-aware effective config, and a doctor command that shows safe fixes | Unknown options fail early; diagnostics name the field and source without its secret value; invalid config leaves data unchanged |
| 4 | Issuer, frontend URL, proxy headers and backchannel URL have distinct security rules. [Hostname guide](https://www.keycloak.org/server/hostname) | Diagnose the full browser-to-proxy-to-server URL chain and verify discovery, callback and cookie settings from the public address | Tests cover a path prefix, TLS termination, separate admin host and forged forwarding headers; never fix a mismatch by relaxing trust |
| 5 | Realm export leaves out live security state and does not give a complete disaster-recovery artifact. [Export limits](https://www.keycloak.org/server/importExport) | Built-in verified backup, restore rehearsal and an upgrade preflight that names the exact rollback boundary | Fresh-host recovery restores keys and data, reconciles security changes, and proves login/deny behavior rather than only row counts |
| 6 | A local development setup should be cheap to create and reset; PostgreSQL is now a required dependency in local work as well as production | Disposable pinned PostgreSQL instances, unique test databases, explicit development mode, health-based readiness, synthetic realms, mock mail/IdP support and public-boundary test helpers | CI runs isolated instances without fixed-port races, sleeps, shared state or a substitute database |
| 7 | Keycloak providers run with the server's privileges and share its class loader; adding a provider can require rebuilding. [Provider model](https://www.keycloak.org/server/configuration-provider) | Built-in Rust providers plus isolated custom Rust workers, a versioned SDK and verified migration bindings | Custom login, policy and mapper behavior survives migration; worker faults stay contained and no JVM/JavaScript backend is required |
| 8 | Cache routing, invalidation and capacity add operational work in clustered deployments. [Cache design](https://www.keycloak.org/server/caching) | PostgreSQL owns durable state, with disposable caches, primary-backed revision checks, bounded pools and visible lock/query limits | Cache eviction and restart do not change auth decisions; a noisy realm cannot exhaust all auth connections |

Priorities rank product value, not delivery order: recovery, admission control and extension boundaries need early design even when their user-facing tools arrive later.

## What these features need underneath

### Safe config changes

Keep native plan/apply separate from the Keycloak import and Admin REST contracts; changing existing endpoint semantics would break compatibility.

Plans cover an explicitly owned set of realm/client/role/flow settings, with secret references rather than secret values; absent fields mean unmanaged unless the schema explicitly says otherwise, and deletion requires an explicit operation.

Bind each plan to the target identity, current config revision and intended changes; recheck authorization, dependencies, revisions and secret references when applying, and report external checks as time-bound observations rather than guarantees.

All config mutation paths, including compatible Admin REST calls, must advance the same revision state; otherwise console edits can evade drift detection and a plan can overwrite them.

Use the existing domain services and validation rules for planning and applying; do not build a second config engine with different permission rules.

A small config change set can be atomic, but a large user import or external LDAP update cannot be promised as one cheap PostgreSQL transaction; reject oversized atomic plans and use a separately documented staged job for bulk work.

Configuration rollback creates a new reviewed change against the current state; it must not rewind credentials, sessions, revocations or external side effects.

### Useful diagnostics without changing protocol errors

Capture bounded reason codes and rule/config IDs from the same execution path that makes the decision; a separate diagnostic policy engine will eventually disagree with production.

Keep public OAuth/SAML/Keycloak errors compatible and privacy-safe; expose detailed explanations only through separately authorized management tools with realm boundaries, redaction, retention limits and audit.

Distinguish a live trace from a simulation: a live trace describes a recorded attempt, while a simulation uses a stated config revision and synthetic inputs and cannot mint tokens, send email or write sessions.

Offer schemas, generated client types, fixture builders, stable CLI JSON output and documented exit codes for native tools; validate generated API descriptions against actual route behavior rather than treating an OpenAPI file as evidence of parity.

### Fast, repeatable local work

Use the production domain and storage code in local mode; bind insecure development listeners to loopback explicitly, isolate every instance, and require deliberate production configuration before public exposure.

Keep synthetic setup behind public CLI/API flows; credentials travel through protected input or memory, never checked-in realm fixtures, logs or command arguments.

Measure time to first successful login, peak startup memory, idle RSS and concurrent test-run throughput on the same hardware and equivalent security settings as Keycloak; no startup or memory multiplier is claimed yet.

## Architecture findings after the scope update

| Status | Finding | Decision or remaining work |
| --- | --- | --- |
| Design chosen; prove recovery | Restore can revive a deleted user, old password, disabled account or removed role | PostgreSQL PITR plus auth quarantine; missing security history requires trusted current-state revalidation before reopening, and session invalidation alone is insufficient |
| Rust replacement designed; prove migration | Java-backed script source cannot run on a Rust-only application backend | Preserve all four hook families with the Rust SDK/host/worker design; require tested ports of active custom behavior before cutover |
| Database choice changed; test fairness | SQLite's global writer no longer applies; PostgreSQL still has hot rows and finite connections | Use concurrent row transactions, split request/worker pools, reserved auth capacity and per-realm admission; measure lock and pool contention |
| Design chosen; prove queries | Admin permission filtering and pagination must agree | PostgreSQL permission-aware filtering precedes pagination/counts; use a consistent snapshot and test tenant boundaries |
| Contract work required | Federation writes and some callbacks have synchronous success/error semantics | Match each HTTP contract; use the outbox only for allowed asynchronous delivery, with explicit ambiguous-result handling for remote effects |
| High | Preview/experimental public APIs are all included without a complete inventory; default-disabled does not reduce the implementation or security work | Freeze the exact profile list and dependencies, estimate each family, and make maturity visible in release claims; removing a nondeprecated profile requires an explicit scope decision |
| HTTP boundary clarified; test browser flows | Upstream console workflows require bootstrap/theme routes and provider metadata beyond the published Admin REST schema | Keep pinned browser journeys; Bun supports the web interface while Rust owns all application APIs, including native setup/provider tools |
| Simpler storage design chosen | A speculative multi-database layer would add work without a supported second database | Use use-case transaction interfaces backed directly by PostgreSQL; no generic database framework or database-portability milestone |
| Performance contract expanded; measure it | Mean throughput alone hides slow tails, hash cost, provider overhead and noisy realms | Freeze paired reference settings, report durable writes, test uniform/80%-skewed traffic and provider workers, and enforce latency/startup/memory budgets with soak/fault evidence |

The Java-backed hooks that need Rust equivalents are documented in the [upstream script API](https://www.keycloak.org/docs/latest/server_development/index.html#_script_providers); permission filtering before pagination is visible in [Keycloak's admin permission design](https://www.keycloak.org/docs/latest/server_admin/index.html#_fine_grained_permissions), and the remaining findings are design analysis of our documents rather than claims of upstream defects.

## Limits of the opportunity

PostgreSQL removes the single-writer database constraint but does not create app HA by itself; the plan now requires multi-node session/replay correctness, provider rollout checks, cache safety and node-failure tests, with database promotion fenced by its operator.

Keycloak already has persistent sessions, policy evaluation, patch-level rolling upgrades, and a supported stateless mode that removes the need for an external cache in multi-cluster deployments; claims that Keycloak always loses sessions or always requires an external cache would be wrong. [Cache state](https://www.keycloak.org/server/caching), [rolling updates](https://www.keycloak.org/server/update-compatibility), [26.8 release](https://www.keycloak.org/2026/10/keycloak-2680-released).

Rust does not remove hashing cost, XML-signature complexity, federation latency, database contention or protocol bugs; native crypto/XML dependencies still need security review.

Rejecting deprecated behavior and executing no Java/JavaScript backend code is required, but dropping maintained customization capabilities is not allowed; Rust providers must preserve the intended decisions, claims and state changes after verified migration.

The most credible differentiation is an auth server that is easier to configure, test, explain and recover while existing clients keep working; the plan now includes setup/migration tools, Rust providers, absolute latency/resource budgets and fair Keycloak comparisons as release work.
