# Feature workflow

Each feature is two commits with versionedcommits and scopedcommits titles (`<scope>: <description>`, scopes listed in CLAUDE.md): a reference recording with no version hint, since it changes no server behaviour, then the implementation (`@minor`), each body explaining its decisions in plain prose, without a "Decision:" label, as the decision record, and no co-author trailer.

1. Read the rule in the pinned source at `~/kcsrc` first; decompile jars only if the source can't be fetched, and say so.
2. Record against the pinned Keycloak 26.8.1: write `tests/reference/<name>.py` with `run(base, secret, record)`, then from `tests/reference` run `python3 batch.py --archive ~/kcarchive/keycloak-26.8.1.tar.gz --record <module>=<baseline>.json`. One reference start takes about 30 s, so batch several recorders per start. Cases that change state get their own fresh user. Login-flow recorders follow redirects inside `login-actions`.
3. Implement, then write `tests/public/<name>_contract.py` comparing with the baseline, and add it to `tests/public/database.sh`. Contract classes make realms and users in `setUpClass`; a test that needs a setting fails when it is missing, through `fixture.requires_setting`.
4. Check: while iterating, build the debug profile (`cargo build -p rs-keycloak-server`) and run only the contracts being changed, from `tests/public`: `python3 fast.py ../../target/debug/rs-keycloak <name>_contract`. Once per goal, before the last commits, build `cargo build --release -p rs-keycloak-server` and run the whole suite with `python3 fast.py --workers 3 ../../target/release/rs-keycloak`; the 500 ms limit counts only on the release build. No test may take over 500 ms; split slow tests or move their setup into `setUpClass`. Then `cargo fmt`, clippy, test and doc.
5. Document each piece in IMPLEMENTATION.md with its remaining differences.

New migrations must also be added to the `MIGRATIONS` list in `crates/storage-postgres/src/lib.rs`. A migration dropped after it ran on the fast database must be undone there by hand (its `rs_schema_history` row and schema).

## Goal size and token use

A goal covers 5 to 8 features from one area of `PLAN.md`, with all their recorders in one `batch.py` start. Every turn re-reads the whole session, so keep what enters it small:

- Find code with `grep -n` and read the matching range with `sed -n`; don't `cat` whole files or print all of `PLAN.md`, `IMPLEMENTATION.md` or `compatibility/reference.lock`.
- Pipe build, test and recorder output through `tail` or `grep`, and show a baseline JSON with `jq` paths, not whole.
- Put independent commands in one Bash call instead of one call each.
- Read the pinned Keycloak source for a rule in an Explore subagent that returns the rule with its file and line numbers, so the source text stays out of the main session.

The server refuses unknown `RS_KEYCLOAK_` variables. The Docker slow suite (`run.sh`, `oidc_contract.py`) runs only when asked.
