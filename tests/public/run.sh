#!/usr/bin/env bash
# Public foundation checks, not the full compatibility/release qualification.
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo build --locked --workspace
python3 tests/public/cli_contract.py target/debug/rs-keycloak
bash tests/public/database.sh
cargo test --locked --workspace
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
