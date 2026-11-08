# Feature workflow

Each feature is two commits with versionedcommits: a reference recording (`@patch`), then the implementation (`@minor`), each body explaining its decisions in plain prose, without a "Decision:" label, as the decision record, and no co-author trailer.

1. Read the rule in the pinned source at `~/kcsrc` first; decompile jars only if the source can't be fetched, and say so.
2. Record against the pinned Keycloak 26.8.1: write `tests/reference/<name>.py` with `run(base, secret, record)`, then from `tests/reference` run `python3 batch.py --archive ~/kcarchive/keycloak-26.8.1.tar.gz --record <module>=<baseline>.json`. One reference start takes about 30 s, so batch several recorders per start. Cases that change state get their own fresh user. Login-flow recorders follow redirects inside `login-actions`.
3. Implement, then write `tests/public/<name>_contract.py` comparing with the baseline, and add it to `tests/public/database.sh`. Contract classes make realms and users in `setUpClass`; a test that needs a setting fails when it is missing, through `fixture.requires_setting`.
4. Check: `cargo build --release -p rs-keycloak-server`, then from `tests/public` run `python3 fast.py --workers 3 ../../target/release/rs-keycloak`. No test may take over 500 ms; split slow tests or move their setup into `setUpClass`. Then `cargo fmt`, clippy, test and doc.
5. Document each piece in IMPLEMENTATION.md with its remaining differences.

New migrations must also be added to the `MIGRATIONS` list in `crates/storage-postgres/src/lib.rs`. A migration dropped after it ran on the fast database must be undone there by hand (its `rs_schema_history` row and schema).

The server refuses unknown `RS_KEYCLOAK_` variables. The Docker slow suite (`run.sh`, `oidc_contract.py`) runs only when asked.
