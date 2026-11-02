"""Client provisioning behavior through the public CLI against a migrated DB."""

import os
from pathlib import Path
import secrets
import subprocess
import sys


binary = str(Path(sys.argv[1]).resolve())
client = "cli-test-" + secrets.token_hex(8)
redirect = "https://client.example.test/callback?app=one"


def invoke(realm, identifier, uri, *, local=True, success=True):
    environment = os.environ.copy()
    environment["RS_KEYCLOAK_LOCAL_DEV"] = str(local).lower()
    result = subprocess.run(
        [binary, "client", "add-public", realm, identifier, uri],
        env=environment, capture_output=True, text=True, timeout=10, check=False,
    )
    assert (result.returncode == 0) == success, "Unexpected client provisioning result"
    return result


invoke("master", client, redirect)
invoke("master", client, redirect)
invoke("master", client, "https://other.example.test/callback", success=False)
# Rejection must leave the original registration usable and idempotent.
invoke("master", client, redirect)
invoke("missing-" + client, client, redirect, success=False)
for uri in (
    "http://client.example.test/callback",
    "https://client.example.test/callback#fragment",
    "javascript:alert(1)",
    "/relative/callback",
):
    invoke("master", client + "-invalid", uri, success=False)
marker = secrets.token_hex(24)
result = invoke("master", client, "https://user:" + marker + "@client.example.test/", success=False)
assert marker not in result.stdout + result.stderr, "Invalid redirect exposed credentials"
invoke("master", client + "-loopback", "http://127.0.0.1:8080/callback")
print("Public client provisioning checks passed")
