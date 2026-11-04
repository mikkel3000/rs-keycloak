"""Userinfo challenges and origin checks, compared with Keycloak 26.8.1 source.

Run with a built rs-keycloak binary path and RS_KEYCLOAK_DATABASE_URL set to a
migrated database. The server starts once per class; each case is one request.
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
import uuid


BINARY = os.path.abspath(sys.argv.pop(1)) if len(sys.argv) > 1 else "rs-keycloak"
REGISTERED = "https://app.example.test"
UNREGISTERED = "https://other.example.test"
CLIENT = "userinfo-contract"
USERINFO = "/realms/master/protocol/openid-connect/userinfo"
ISSUER = "https://login.example.test/realms/master"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def private_numbers(pem):
    """Reads n and d from OpenSSL text output; the key stays in pipes."""
    text = subprocess.run(
        ["openssl", "pkey", "-noout", "-text"], input=pem,
        capture_output=True, timeout=5, check=True,
    ).stdout.decode()

    def number(name):
        match = re.search(name + r":\s*\n((?:\s+[0-9a-f:]+\n)+)", text)
        return int(re.sub(r"[\s:]", "", match.group(1)), 16)

    return number("modulus"), number("privateExponent")


class UserinfoContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cli = lambda *args: subprocess.run(
            [BINARY, *args], capture_output=True, timeout=10, check=False,
        )
        assert cli("db", "migrate").returncode == 0, "Migration failed"
        # Bootstrap fails harmlessly when an earlier run created master.
        subprocess.run(
            [BINARY, "bootstrap-admin", "userinfo-admin"],
            input=secrets.token_urlsafe(32) + "\n", text=True,
            capture_output=True, timeout=15, check=False,
        )
        assert cli("client", "add-public", "master", CLIENT, REGISTERED + "/cb").returncode == 0
        assert cli("client", "add-web-origin", "master", CLIENT, REGISTERED).returncode == 0
        pem = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
            capture_output=True, timeout=15, check=True,
        ).stdout
        der = subprocess.run(
            ["openssl", "pkcs8", "-topk8", "-nocrypt", "-outform", "DER"],
            input=pem, capture_output=True, timeout=5, check=True,
        ).stdout
        cls.modulus, cls.exponent = private_numbers(pem)
        with socket.socket() as http_socket, socket.socket() as management_socket:
            http_socket.bind(("127.0.0.1", 0))
            management_socket.bind(("127.0.0.1", 0))
            cls.port = http_socket.getsockname()[1]
            management = management_socket.getsockname()[1]
        environment = os.environ.copy()
        environment.update({
            "RS_KEYCLOAK_HTTP_LISTEN": f"127.0.0.1:{cls.port}",
            "RS_KEYCLOAK_MANAGEMENT_LISTEN": f"127.0.0.1:{management}",
            "RS_KEYCLOAK_ISSUER": "https://login.example.test",
            "RS_KEYCLOAK_SIGNING_KEY_PKCS8": base64.b64encode(der).decode(),
        })
        cls.process = subprocess.Popen(
            [BINARY, "serve"], env=environment,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 15
        while True:
            assert cls.process.poll() is None, "Server exited at startup"
            try:
                status, _, body = cls.request("GET", "/realms/master/protocol/openid-connect/certs")
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
    def request(cls, method, path, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=2)
        try:
            connection.request(method, path, headers=headers or {})
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

    def sessionless_token(self, client=CLIENT):
        now = int(time.time())
        return self.sign({
            "typ": "Bearer", "iss": ISSUER, "sub": str(uuid.uuid4()), "aud": client,
            "iat": now, "exp": now + 60, "jti": str(uuid.uuid4()), "azp": client,
            "sid": str(uuid.uuid4()), "scope": "openid",
        })

    def assert_challenge(self, headers, description):
        expected = 'Bearer realm="master"'
        if description:
            expected += f', error="invalid_token", error_description="{description}"'
        self.assertEqual(headers.get("www-authenticate"), expected)
        self.assertEqual(headers.get("cache-control"), "no-store")

    def assert_cors(self, headers, origin):
        self.assertEqual(headers.get("access-control-allow-origin"), origin)
        self.assertEqual(headers.get("access-control-allow-credentials"), "true")
        exposed = {value.strip() for value in headers.get("access-control-expose-headers", "").split(",")}
        self.assertIn("WWW-Authenticate", exposed)

    def test_missing_token_without_origin_has_realm_challenge_only(self):
        status, headers, body = self.request("GET", USERINFO)
        self.assertEqual(status, 401)
        self.assert_challenge(headers, None)
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertEqual(body, b"")

    def test_missing_token_allows_any_origin_before_client_is_known(self):
        status, headers, _ = self.request("GET", USERINFO, {"Origin": UNREGISTERED})
        self.assertEqual(status, 401)
        self.assert_challenge(headers, None)
        self.assert_cors(headers, UNREGISTERED)

    def test_unverifiable_token_allows_any_origin(self):
        status, headers, _ = self.request("GET", USERINFO, {
            "Origin": UNREGISTERED, "Authorization": "Bearer not-a-token",
        })
        self.assertEqual(status, 401)
        self.assert_challenge(headers, "Token verification failed")
        self.assert_cors(headers, UNREGISTERED)

    def test_verified_token_from_unregistered_origin_is_forbidden(self):
        status, headers, body = self.request("GET", USERINFO, {
            "Origin": UNREGISTERED, "Authorization": "Bearer " + self.sessionless_token(),
        })
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "Invalid origin"})
        self.assertNotIn("access-control-allow-origin", headers)

    def test_verified_token_without_session_reports_session_not_found(self):
        status, headers, _ = self.request("GET", USERINFO, {
            "Origin": REGISTERED, "Authorization": "Bearer " + self.sessionless_token(),
        })
        self.assertEqual(status, 401)
        self.assert_challenge(headers, "user_session_not_found")
        self.assert_cors(headers, REGISTERED)

    def test_unknown_client_allows_any_origin_and_reports_it(self):
        token = self.sessionless_token(client="missing-" + uuid.uuid4().hex)
        status, headers, _ = self.request("GET", USERINFO, {
            "Origin": UNREGISTERED, "Authorization": "Bearer " + token,
        })
        self.assertEqual(status, 401)
        self.assert_challenge(headers, "Client not found")
        self.assert_cors(headers, UNREGISTERED)

    def test_preflight_is_cached_for_one_hour(self):
        status, headers, _ = self.request("OPTIONS", USERINFO, {
            "Origin": UNREGISTERED, "Access-Control-Request-Method": "GET",
        })
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("access-control-max-age"), "3600")


if __name__ == "__main__":
    unittest.main()
