# Rust style

Follow the Google Rust style guide, including source-module imports, leaf module
implementations, named types for invariants, documented public APIs, and
borrowing when a copy is unnecessary. `cargo fmt --check`, Clippy, and
`cargo doc` supplement review; rustfmt does not enforce every guide rule.
Chromium-specific async and thread rules and the Fuchsia-specific mutex rule do
not apply to this standalone Tokio service. Review any further exceptions here.
