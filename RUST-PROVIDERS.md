# Rust provider contract

Custom authentication, authorization and claim mapping are required capabilities of the replacement; the supported implementation language for backend extensions is Rust, with no JVM, JavaScript engine or runtime compilation.

Keycloak exposes script hooks for authenticators, policies and OIDC/SAML mappers; scripts can access Java-backed host objects, so installing a JavaScript interpreter would not meet either behavioral parity or the Rust-only requirement. [Keycloak provider hooks](https://www.keycloak.org/docs/latest/server_development/index.html#_script_providers).

## Capability coverage

| Existing use | Rust alternative | Acceptance evidence |
| --- | --- | --- |
| Script authenticator/action | Rust authenticator returning a typed challenge, success, required action or failure | Same ordered flow transitions, challenge fields, session updates and failure behavior |
| JavaScript authorization policy | Rust policy returning grant/deny/abstain with a bounded reason code | Same decisions under positive/negative logic, aggregates, time/attribute conditions and permission evaluation |
| OIDC script mapper | Rust claim mapper operating on typed user/client/session/claim input | Same claim names, JSON types, audiences, scopes and access/ID token placement |
| SAML script mapper | Rust assertion-attribute mapper | Same attribute names, name formats and values; the host owns assertion signing and encryption |
| Custom Java provider performing maintained work | Port to the relevant Rust provider interface, with host capabilities for allowed external work | Same HTTP behavior and persistent effects for the supported configuration |

Ship configurable built-in providers for common conditions, attribute/role mappings, group checks and policy composition; known upstream default policies get reviewed Rust equivalents, not a requirement that every operator write code.

Do not convert an unknown script into an allow policy, skip an authenticator, omit a claim or treat a provider timeout as success; preserve the reference's policy combination semantics while making host failures fail closed.

## Host and worker boundary

Built-in reviewed providers execute in the Rust service; custom Rust providers execute as separate Rust worker processes so a loop, crash or memory fault can be contained and terminated without killing the auth server.

Use a versioned, length-framed local IPC protocol with typed request/response schemas; no Rust dynamic-library ABI, unrestricted shared memory or remote code loading is part of the contract.

The SDK defines `Authenticator`, `AuthorizationPolicy`, `OidcMapper` and `SamlMapper` concepts with schema-versioned inputs and results; SDK types are translated at the worker boundary rather than exposing SQLx rows or internal domain layouts.

Inputs contain only the allowed realm-scoped data, config/provider revision, operation identity and deadline; private keys, raw passwords, DB credentials, bearer tokens and other realms' data are not sent to workers.

Host capabilities provide scoped attribute lookups, credential verification results, approved outbound connector calls and proposed state changes; every capability is authorized by both the installed manifest and the invoking operation's permissions.

Workers cannot access PostgreSQL, secret mounts or the network directly; run with an unprivileged identity, isolated filesystem, restricted inherited handles and OS-enforced process, memory, CPU and syscall limits.

Scope worker instances to a realm and provider revision, reuse warm workers within that scope, and evict idle workers under a bounded global memory/process budget; a new realm must not inherit another realm's in-memory extension state.

Start with at most eight resident custom workers per node, 64 MiB per worker, 64 KiB request/response frames and a 100 ms deadline for pure policy/mapper calls; authenticators use a declared bounded budget within the HTTP deadline, and larger limits require an explicit deployment profile with load/security tests.

Use a bounded fair queue and hard per-call deadline; kill and replace stuck workers, discard late replies, limit restart storms and expose a clear provider-unavailable result without falling back to a weaker flow.

The host revalidates result shape, permitted claims/actions, provider revision and account/session revisions before committing; workers do not hold SQL transactions open, grant themselves permissions or mint signed tokens.

Group pure mapper work only when ordering and state dependencies allow it; measure IPC, cold-worker and warm-worker costs, and retain separate performance gates for deployments with custom providers.

## Installation and upgrades

Developers build providers from Rust source in CI against a pinned SDK/toolchain; artifacts include signed provenance, a digest, provider ID/version, supported protocol versions, config schema, requested capabilities and resource limits.

Operators install reviewed artifacts through a privileged management command/API; accepting Rust source through a public login/admin endpoint or invoking Cargo/rustc in the server is forbidden.

Register artifacts on every serving node before binding a flow; readiness checks required provider availability, and configuration activation fails if any required node lacks the compatible artifact.

Use a node capability registry and rollout version bounds for provider upgrades; retain the old provider revision until in-flight flows finish or are explicitly invalidated, and do not change an active flow's provider logic mid-request.

Install/upgrade/remove operations are audited, scoped to operator roles and idempotent by artifact digest; removal is blocked while an active configuration depends on the provider.

## Migrating Java and JavaScript customization

`migration inspect` inventories script bodies, JAR provider references, configuration, execution order and dependent resources without executing source code; reports use source digests and component IDs rather than dumping source that may contain secrets.

Map each dependency to a built-in Rust provider or a custom Rust artifact, and record source digest, original provider/component ID, target artifact/config version and evidence of matching behavior in a signed migration manifest.

Automatically map only reviewed, exact known upstream defaults; arbitrary source needs a Rust port and tests, and a code/config change invalidates the old equivalence result.

Run paired fixtures through the source Keycloak HTTP APIs and the target Rust APIs, covering allow/deny, missing input, errors, state changes and concurrency; the Java reference server runs only in isolated development/migration verification, never as an rs-keycloak production dependency.

Preserve public resource IDs, supported config values and wire behavior through compatibility bindings where possible; native artifact installation belongs to a separate management API and cannot be smuggled through a normal realm-admin configuration write.

Raw JavaScript authoring/upload and loading Java binaries cannot remain unchanged when their runtime is removed; document these authoring exceptions and required admin-automation changes, while requiring application-facing flows to match after the port.

An import with an unmapped active provider fails before mutation with a dependency report; migration verification and traffic cutover remain blocked until all active behavior is covered or the operator explicitly approves a configuration change.

## Release gates

Require tested Rust alternatives for all four script hook families, SDK examples, provider lifecycle UI/CLI, and a migration fixture using custom login, authorization and claims together.

Exercise malformed/oversized IPC, denied host capabilities, attempted cross-realm access, worker crash/loop, process eviction, exhausted budgets, stale revisions, mixed-version rollout and provider rollback through public flows.

The extension system must pass independent security review and runtime dependency checks proving that production auth paths do not require a JVM, JavaScript interpreter or compiler; signed Rust provenance is not a substitute for sandbox and behavior tests.
