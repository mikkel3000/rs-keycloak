# rs-keycloak

A planned, complete Keycloak replacement with HTTP API compatibility, a Rust-only application backend and PostgreSQL; maintained script capabilities get Rust providers, legacy/deprecated features remain excluded, and Bun may support the web interface.

The first production release must cover the full agreed API contract, pass security and load tests, and have tested upgrades and recovery; there is no MVP release.

- [Build plan](PLAN.md): architecture, storage, security, delivery steps, and release gates.
- [Compatibility contract](COMPATIBILITY.md): Keycloak baseline, scope, exclusions, and test rules.
- [Rust providers](RUST-PROVIDERS.md): custom login, policy and mapper support without Java or server-side JavaScript.
- [Opportunities and review](OPPORTUNITIES.md): developer experience improvements and architecture gaps to resolve.

Status: implementation in progress; this is not a complete Keycloak replacement or a production release. PostgreSQL migrations, bootstrap and client setup, management routes, bounded password work, PKCE validation and RSA signing primitives are implemented; public authentication and the full compatibility contract remain incomplete.

Build with `cargo build --locked --workspace` using the pinned toolchain. Run `bash tests/public/run.sh` with Docker, Python 3, Node.js 22 or later and OpenSSL available; the suite creates a disposable PostgreSQL container and checks public CLI behavior before Rust tests and lint checks. OpenSSL generates test keys in memory. The adapter fixture downloads and checks the digest of keycloak-js 26.2.2, then uses Node only as a test client with in-memory browser stubs. These checks do not establish full HTTP compatibility or production readiness.

See [implementation evidence](IMPLEMENTATION.md) for tested behavior and [the production plan](PLAN.md) for the required remaining scope.
