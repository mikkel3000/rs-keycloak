"""Userinfo challenges and origin checks, compared with Keycloak 26.8.1 source.

Run with a built rs-keycloak binary path; see fixture.py for the database.
"""

import json
import time
import unittest
import uuid

from fixture import ENDPOINT, ISSUER, ServerCase, cli


REGISTERED = "https://app.example.test"
UNREGISTERED = "https://other.example.test"
CLIENT = "userinfo-contract"
USERINFO = ENDPOINT + "/userinfo"


class UserinfoContract(ServerCase):
    @classmethod
    def provision(cls):
        assert cli("client", "add-public", "master", CLIENT, REGISTERED + "/cb").returncode == 0
        assert cli("client", "add-web-origin", "master", CLIENT, REGISTERED).returncode == 0

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
