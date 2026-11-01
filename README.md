# rs-keycloak

A planned, complete Keycloak replacement with HTTP API compatibility, a Rust-only application backend and PostgreSQL; maintained script capabilities get Rust providers, legacy/deprecated features remain excluded, and Bun may support the web interface.

The first production release must cover the full agreed API contract, pass security and load tests, and have tested upgrades and recovery; there is no MVP release.

- [Build plan](PLAN.md): architecture, storage, security, delivery steps, and release gates.
- [Compatibility contract](COMPATIBILITY.md): Keycloak baseline, scope, exclusions, and test rules.
- [Rust providers](RUST-PROVIDERS.md): custom login, policy and mapper support without Java or server-side JavaScript.
- [Opportunities and review](OPPORTUNITIES.md): developer experience improvements and architecture gaps to resolve.

Status: planning only; no server or compatibility tests have been built or run.
