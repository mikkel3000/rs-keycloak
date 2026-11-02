# Reference contract

`reference.lock` pins the upstream tag's resolved commit and the Quay multi-platform image index by SHA-256; `source/` contains unmodified Apache-2.0 upstream files with source notices, and each file's digest is locked.

`features.json` records all 80 `Profile.Feature` entries, including version, dependencies, lifecycle and explicit deprecated flags; flags remain source facts, and `requires-surface-review` is not an exclusion or a parity claim.

`source-inventory.json` lists 180 tagged resource/endpoint Java source candidates; the list is not a complete HTTP inventory because inherited routes, subresource locators, provider-generated paths and browser routes need review.

`operations.json` records 634 source-declared HTTP methods with file/line/hash evidence, with unresolved public paths and planned status; no reviewed operations are claimed; the full route/method/profile matrix, permission/schema/effect mapping, exclusions with evidence, browser/client pins, PostgreSQL runtime validation, threat model, dependency audit and performance baseline remain release blockers.

## Public reference checks

Run from the repository root:

```sh
tests/reference/reference.sh start
tests/reference/reference.sh check
tests/reference/reference.sh check --target http://127.0.0.1:8080
tests/reference/reference.sh stop
```

Wait for the reference HTTP listener before `check`; startup failures cause checks to fail rather than skip, and the named disposable container must not share a port/name with another run.

The harness uses Keycloak's standard `start-dev` entry point and an ephemeral development database, exposes only loopback port 18080, creates no admin credentials and checks public discovery, JWKS shape and unknown-realm errors; it does not claim production PostgreSQL qualification, authenticated flow parity, token signature verification, browser coverage or performance evidence.

`check.py --reference URL [--target URL]` can test separately managed reference/target deployments; the smoke suite compares metadata fields/grants/response types without stripping token data or masking issuer relationships.

Do not use the development container for production or feed it real user data; production qualification requires the complete pinned PostgreSQL profile, client suites and all contract gates.

## Recorded run

The source digests, 80 unique feature keys, CLI help and shell syntax passed local checks; the pinned image layer pull failed at the Quay CDN with HTTP 403, and `sbx` was not installed.

The official 26.8.1 distribution then passed the public smoke check on OpenJDK 25.0.4 with isolated temporary development data and a loopback listener; this was a native test reference rather than an isolated container or a production PostgreSQL profile.

To reproduce the distribution fallback, fetch the exact URL in `reference.lock`, run `tests/reference/reference.sh start-distribution /path/to/keycloak-26.8.1.tar.gz` in one terminal, and run the standard `check` command in another terminal; the launcher checks the archive SHA-256 before extraction and deletes temporary data on exit.

To regenerate source-declared operations from the exact source archive, use `python3 compatibility/inventory.py --source /path/to/extracted/source --output compatibility/operations.json`; a semantic route/profile/permission review is still required, and a generated count is not a coverage result.

The Java admin client is independently released as 26.0.12, evidenced by the Maven Central POM, while the tagged console dependency lock resolves `keycloak-js` to 26.2.2; neither client has passed runtime qualification here.

## OAuth reference fixture

Run `tests/reference/oauth.py --archive /path/to/keycloak-26.8.1.tar.gz` with Python 3.12+, OpenJDK 25 and OpenSSL on PATH; the launcher verifies the archive digest, starts a fresh loopback reference on port 18081, uses an in-memory bootstrap service-account secret, and removes the temporary realm/data after the run.

The fixture imports synthetic realm/client/user data through Admin REST and exercises HTTP login forms/cookies, authorization code with S256 PKCE, nonce/state/issuer/audience/time binding, public JWKS signature verification through OpenSSL, userinfo, refresh and replay/wrong-verifier denial; child logs are suppressed and secrets/tokens/signatures stay in memory and anonymous pipes.

The HTTP form client is not browser-engine automation, uses loopback-specific secure-cookie handling and is not an independent OIDC client library; signature checks currently cover the fixture's RS256 algorithm, and no paired target parity is claimed.
