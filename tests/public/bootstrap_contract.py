"""Exercise one-time bootstrap against a fresh migrated disposable database."""

from concurrent.futures import ThreadPoolExecutor
import secrets
import subprocess
import sys

import oidc_contract


binary = sys.argv[1]
password = secrets.token_urlsafe(32)


def bootstrap(username):
    return subprocess.run(
        [binary, "bootstrap-admin", username], input=password + "\n",
        text=True, capture_output=True, timeout=15, check=False,
    )


with ThreadPoolExecutor(max_workers=2) as executor:
    results = list(executor.map(bootstrap, ("first-admin", "second-admin")))
assert sum(result.returncode == 0 for result in results) == 1, "Bootstrap must have exactly one winner"
for result in results:
    assert password not in result.stdout + result.stderr, "Password leaked in CLI output"
repeat = bootstrap("third-admin")
assert repeat.returncode != 0, "Repeated bootstrap must fail"
assert password not in repeat.stdout + repeat.stderr, "Password leaked in repeated bootstrap"
print("Concurrent bootstrap and repeat rejection passed")
winner = ("first-admin", "second-admin")[next(i for i, result in enumerate(results) if result.returncode == 0)]
oidc_contract.run(binary, winner, password)
