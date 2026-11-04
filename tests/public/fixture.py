"""Shared fast-contract fixture: one server per test class, independent signing.

Contracts call `ServerCase.main()`, which takes the built binary path as the
first argument. RS_KEYCLOAK_DATABASE_URL must name a database the contract may
migrate; the fixture creates the master realm once and reuses it afterwards.
"""

import base64
import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
import unittest
import urllib.parse


BINARY = os.path.abspath(sys.argv.pop(1)) if len(sys.argv) > 1 else "rs-keycloak"
ISSUER_BASE = "https://login.example.test"
ISSUER = ISSUER_BASE + "/realms/master"
ENDPOINT = "/realms/master/protocol/openid-connect"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def cli(*args, stdin=None):
    """Runs one CLI command; stdin carries secrets so they stay off argv."""
    return subprocess.run(
        [BINARY, *args], input=stdin, text=True,
        capture_output=True, timeout=15, check=False,
    )


def private_numbers(pem):
    """Reads n, e and d from OpenSSL text output; the key stays in pipes."""
    text = subprocess.run(
        ["openssl", "pkey", "-noout", "-text"], input=pem,
        capture_output=True, timeout=5, check=True,
    ).stdout.decode()

    def number(name):
        match = re.search(name + r":\s*\n((?:\s+[0-9a-f:]+\n)+)", text)
        return int(re.sub(r"[\s:]", "", match.group(1)), 16)

    public = int(re.search(r"publicExponent: (\d+)", text).group(1))
    return number("modulus"), public, number("privateExponent")


class ServerCase(unittest.TestCase):
    """Starts `rs-keycloak serve` once per class; each test should be one exchange."""

    @classmethod
    def provision(cls):
        """Subclasses register their clients through the public CLI."""

    @classmethod
    def setUpClass(cls):
        assert cli("db", "migrate").returncode == 0, "Migration failed"
        # Bootstrap fails harmlessly when an earlier contract created master.
        cli("bootstrap-admin", "contract-admin", stdin=secrets.token_urlsafe(32) + "\n")
        cls.provision()
        pem = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
            capture_output=True, timeout=15, check=True,
        ).stdout
        der = subprocess.run(
            ["openssl", "pkcs8", "-topk8", "-nocrypt", "-outform", "DER"],
            input=pem, capture_output=True, timeout=5, check=True,
        ).stdout
        cls.modulus, cls.public_exponent, cls.exponent = private_numbers(pem)
        with socket.socket() as http_socket, socket.socket() as management_socket:
            http_socket.bind(("127.0.0.1", 0))
            management_socket.bind(("127.0.0.1", 0))
            cls.port = http_socket.getsockname()[1]
            management = management_socket.getsockname()[1]
        environment = os.environ.copy()
        environment.update({
            "RS_KEYCLOAK_HTTP_LISTEN": f"127.0.0.1:{cls.port}",
            "RS_KEYCLOAK_MANAGEMENT_LISTEN": f"127.0.0.1:{management}",
            "RS_KEYCLOAK_ISSUER": ISSUER_BASE,
            "RS_KEYCLOAK_SIGNING_KEY_PKCS8": base64.b64encode(der).decode(),
            "RS_KEYCLOAK_SECRET_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
        })
        cls.process = subprocess.Popen(
            [BINARY, "serve"], env=environment,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 15
        while True:
            assert cls.process.poll() is None, "Server exited at startup"
            try:
                status, _, body = cls.request("GET", ENDPOINT + "/certs")
                if status == 200:
                    break
            except OSError:
                pass
            assert time.monotonic() < deadline, "Server did not start"
            time.sleep(0.02)
        cls.kid = json.loads(body)["keys"][0]["kid"]

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=10)

    @classmethod
    def request(cls, method, path, headers=None, form=None, body=None):
        headers = dict(headers or {})
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        connection = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=2)
        try:
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
        finally:
            connection.close()

    def sign(self, claims):
        """Signs RS256 independently of the Rust signer (RFC 8017 PKCS#1 v1.5)."""
        header = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": self.kid}).encode())
        payload = b64(json.dumps(claims).encode())
        width = (self.modulus.bit_length() + 7) // 8
        digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
        digest_info += hashlib.sha256(f"{header}.{payload}".encode()).digest()
        encoded = b"\x00\x01" + b"\xff" * (width - len(digest_info) - 3) + b"\x00" + digest_info
        signature = pow(int.from_bytes(encoded, "big"), self.exponent, self.modulus)
        return f"{header}.{payload}.{b64(signature.to_bytes(width, 'big'))}"

    def verify(self, token):
        """Returns claims after checking the RS256 signature with the public key."""
        header, payload, signature = token.split(".")
        decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        self.assertEqual(json.loads(decode(header))["kid"], self.kid)
        width = (self.modulus.bit_length() + 7) // 8
        digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
        digest_info += hashlib.sha256(f"{header}.{payload}".encode()).digest()
        expected = b"\x00\x01" + b"\xff" * (width - len(digest_info) - 3) + b"\x00" + digest_info
        recovered = pow(int.from_bytes(decode(signature), "big"), self.public_exponent, self.modulus)
        self.assertEqual(recovered.to_bytes(width, "big"), expected, "signature mismatch")
        return json.loads(decode(payload))
