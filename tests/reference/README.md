# Pinned reference HTTP fixtures

Run `tests/reference/tokens.py --archive /path/to/keycloak-26.8.1.tar.gz` with Python 3.12+, OpenJDK 25 and OpenSSL; the launcher checks the archive digest from `compatibility/reference.lock`, starts an isolated temporary upstream server on loopback port 18081, and removes its realm/data after the run.

The suite compares 91 public HTTP observations with `token-observations.json`, covering public/confidential clients, token authentication, audience/ownership checks, access/refresh/ID/unknown tokens, expired access tokens, refresh/session effects, and metadata/token/userinfo CORS; token and claim values are excluded from the snapshot, so these observations do not establish full response or target parity.

The default `no-aud-owner` client has no audience mapper and cannot introspect its own access token as active; `conf-owner`, `conf-other` and `short-owner` have explicit self-audience mappers, and `public-owner` has a mapper adding `conf-other` to its access-token audience.

The shared-session fixture signs in two clients through the same real upstream SSO cookies and verifies that revoking one client's refresh token preserves the sibling client's access, refresh and userinfo; the short-token fixture uses an explicit one-second access-token lifetime, without claiming expired-refresh or offline-token coverage.

Synthetic bootstrap/client/user secrets and tokens remain in memory, upstream process output is suppressed, and snapshots retain only selected error/active fields, field names and response headers; the only header normalization replaces the random fixture realm in `WWW-Authenticate` with `{realm}`.

`--record` emits redacted observations without comparing the baseline for an explicit reviewed contract update; normal runs fail if the baseline is missing or any observed case changes, and `--port` selects another loopback reference port.

`oauth.py` separately tests public/confidential login forms, code/PKCE, signed token validation and client-authentication errors; the HTTP form client does not replace browser-engine or independent protocol-client qualification.
