# Contract threat cases

This list starts the test inventory and is not an independent security review or a completed threat model.

| Boundary | Required public proof | Status |
| --- | --- | --- |
| Realm and admin permissions | Cross-realm IDs, master-realm roles, forged scope, list/search leakage and denied mutations | Pending |
| Authorization codes and refresh | Concurrent consume, replay, stale credentials, client/redirect/PKCE binding and failed commit | Pending |
| Browser sessions | CSRF, session fixation, cookie scope, proxy paths, origin checks and logout replay | Pending |
| Broker and federation | Account-link takeover, unsigned/misbound assertions, external outage and sync race | Pending |
| SAML and signed tokens | Signature verification, XML wrapping, destination/audience, replay and key rotation | Pending |
| Providers | Unmapped active code, unsigned artifact, cross-realm capabilities, worker crash/deadline and stale revision | Pending |
| Imports and recovery | Pre-mutation validation, credential/grant rollback, restored key availability and quarantined egress | Pending |
| Availability and logs | Request/CPU/queue limits, malformed input, secret redaction and tenant load isolation | Pending |

`tests/reference/check.py` only proves the three listed anonymous HTTP smoke checks when run successfully; JWKS shape checks do not prove cryptographic validation.
