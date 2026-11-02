"""Exercise management HTTP and shutdown through the installed server command."""

import http.client
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time


binary = str(Path(sys.argv[1]).resolve())
environment = os.environ.copy()
environment["RS_KEYCLOAK_ISSUER"] = "https://login.example.test"
# The reservation remains held until just before spawn; a competing process
# taking the port causes a test failure rather than probing an unrelated server.
with socket.socket() as reservation:
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
environment["RS_KEYCLOAK_MANAGEMENT_LISTEN"] = f"127.0.0.1:{port}"
process = subprocess.Popen(
    [binary, "serve"], env=environment, stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, text=True,
)


def request(method, path):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


try:
    deadline = time.monotonic() + 10
    while True:
        assert process.poll() is None, "Server exited before becoming live"
        try:
            if request("GET", "/health/live") == 200:
                break
        except (OSError, http.client.HTTPException):
            pass
        assert time.monotonic() < deadline, "Management listener did not become live"
        time.sleep(0.05)
    assert request("GET", "/health/ready") == 503, "Incomplete server reported readiness"
    assert request("POST", "/health/live") == 405
    assert request("GET", "/realms/master") == 404, "Public route leaked on management port"
    assert process.poll() is None, "Test reached a different process"
    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=5)
    assert process.returncode == 0, "SIGTERM did not stop the server cleanly"
    # Bind the same endpoint to prove shutdown released the listening socket.
    with socket.socket() as released:
        released.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        released.bind(("127.0.0.1", port))
    print("Public management lifecycle checks passed")
finally:
    if process.poll() is None:
        process.kill()
    process.communicate(timeout=5)
