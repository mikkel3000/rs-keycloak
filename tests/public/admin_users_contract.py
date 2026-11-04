"""User administration compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/admin-user-observations.json. The user
representation omits Keycloak's `access` map until admin permissions exist.
"""

import base64
import hashlib
import json
import pathlib
import re
import secrets
import unittest
import urllib.parse

from fixture import ENDPOINT, ISSUER_BASE, ServerCase, cli


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/admin-user-observations.json").read_text()
)["observations"]
RUN = secrets.token_hex(4)
ADMIN, ADMIN_SECRET = "user-admin-" + RUN, secrets.token_urlsafe(40)
CALLBACK = "https://app.example.test/callback"


class AdminUsersContract(ServerCase):
    @classmethod
    def provision(cls):
        assert cli("client", "add-confidential", "master", ADMIN, CALLBACK, stdin=ADMIN_SECRET + "\n").returncode == 0
        assert cli("client", "enable-service-account", "master", ADMIN).returncode == 0
        assert cli("client", "grant-master-admin", ADMIN).returncode == 0

    def setUp(self):
        status, _, body = self.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": ADMIN, "client_secret": ADMIN_SECRET})
        self.assertEqual(status, 200)
        self.token = json.loads(body)["access_token"]
        self.realm = "users-" + secrets.token_hex(6)
        self.assertEqual(self.call("POST", "/admin/realms", {"realm": self.realm, "enabled": True})[0], 201)
        self.users = f"/admin/realms/{self.realm}/users"

    def tearDown(self):
        self.call("DELETE", "/admin/realms/" + self.realm)

    def call(self, method, path, payload=None, raw=None, token=True):
        headers = {"Authorization": "Bearer " + self.token} if token else {}
        body = raw if raw is not None else (json.dumps(payload) if payload is not None else None)
        if body is not None:
            headers["Content-Type"] = "application/json"
        return self.request(method, path, headers, body=body)

    def assert_case(self, response, label):
        status, headers, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        pattern = expected.get("location_pattern")
        if pattern:
            prefix = pattern.replace("{base}", ISSUER_BASE).replace("{realm}", self.realm).removesuffix("{id}")
            self.assertTrue(headers.get("location", "").startswith(prefix), label)
        else:
            self.assertIsNone(headers.get("location"), label)
        self.assertEqual(not body, expected["empty_body"], label)
        parsed = json.loads(body) if body else None
        if "body" in expected:
            for key, value in expected["body"].items():
                self.assertEqual(parsed.get(key), value, f"{label}: {key}")
        if "value" in expected:
            self.assertEqual(parsed, expected["value"], label)
        if "usernames" in expected:
            self.assertEqual(sorted(item["username"] for item in parsed), expected["usernames"], label)
            self.assertEqual({item["username"]: item["enabled"] for item in parsed}, expected["enabled_by_username"], label)
        return parsed

    def create_reference_users(self):
        created = self.call("POST", self.users, {"username": "Reference-User", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "Reference@Example.invalid", "emailVerified": True})
        self.assert_case(created, "create/success")
        self.assert_case(self.call("POST", self.users, {"username": "disabled-user", "enabled": False}), "create/disabled")
        self.assert_case(self.call("POST", self.users, {"username": "default-user"}), "create/default-enabled")
        return created[1]["location"].rsplit("/", 1)[1]

    def test_create_and_read_user(self):
        user_id = self.create_reference_users()
        read = self.assert_case(self.call("GET", f"{self.users}/{user_id}"), "get/success")
        expected_fields = set(REFERENCE["get/success"]["body_fields"]) - {"access"}
        self.assertEqual(set(read), expected_fields)

    def test_duplicates_are_case_insensitive(self):
        self.create_reference_users()
        self.assert_case(self.call("POST", self.users, {"username": "reference-user", "enabled": True}), "create/duplicate-case")
        self.assert_case(self.call("POST", self.users, {"username": "other-user", "email": "reference@example.invalid"}), "create/duplicate-email")

    def test_create_validation(self):
        self.assert_case(self.call("POST", self.users, {"enabled": True}), "create/missing-username")
        self.assert_case(self.call("POST", self.users, raw="{"), "create/malformed-json")
        self.assert_case(self.call("POST", self.users, {"username": "nobody"}, token=False), "create/no-token")
        self.assert_case(self.call("POST", "/admin/realms/unknown-" + RUN + "/users", {"username": "nobody"}), "create/unknown-realm")
        status, _, body = self.call("POST", self.users, {"username": "x", "credentials": []})
        self.assertEqual((status, json.loads(body)), (400, {"errorMessage": "Unsupported user field: credentials"}))

    def test_search_and_count(self):
        self.create_reference_users()
        self.assert_case(self.call("GET", self.users + "?username=Reference-User&exact=true"), "search/exact")
        self.assert_case(self.call("GET", self.users + "?username=reference"), "search/prefix")
        self.assert_case(self.call("GET", self.users), "search/all")
        self.assert_case(self.call("GET", self.users + "/count"), "count")
        self.assertEqual(self.call("GET", self.users + "?email=x")[0], 400)

    def test_unknown_user(self):
        missing = "00000000-0000-0000-0000-000000000000"
        self.assert_case(self.call("GET", f"{self.users}/{missing}"), "get/unknown")
        self.assert_case(self.call("PUT", f"{self.users}/{missing}/reset-password", {"type": "password", "value": "x" * 20, "temporary": False}), "password/unknown-user")

    def test_reset_password_enables_login_and_delete_removes_user(self):
        user_id = self.create_reference_users()
        password = secrets.token_urlsafe(32)
        reset = f"{self.users}/{user_id}/reset-password"
        self.assert_case(self.call("PUT", reset, {"type": "password", "value": ""}), "password/empty")
        self.assert_case(self.call("PUT", reset, {"type": "password", "value": password, "temporary": False}), "password/success")
        self.assertEqual(cli("client", "add-public", self.realm, "login-app", CALLBACK).returncode, 0)
        claims = self.login("reference-user", password)
        self.assertEqual(claims["sub"], user_id)
        self.assertEqual(claims["realm_access"]["roles"], sorted([f"default-roles-{self.realm}", "offline_access", "uma_authorization"]))
        self.assertEqual(REFERENCE["login/after-reset"]["status"], 200)
        self.assert_case(self.call("DELETE", f"{self.users}/{user_id}"), "delete/success")
        self.assert_case(self.call("DELETE", f"{self.users}/{user_id}"), "delete/repeat")

    def login(self, username, password):
        """Browser-form login with PKCE in the test realm; returns access claims."""
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        query = urllib.parse.urlencode({"client_id": "login-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "code_challenge": challenge, "code_challenge_method": "S256", "state": "s"})
        status, headers, body = self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/auth?{query}")
        self.assertEqual(status, 200)
        action = re.search(r'action="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        cookie = headers["set-cookie"].split(";", 1)[0]
        status, headers, _ = self.request("POST", action, {"Cookie": cookie}, {"username": username, "password": password})
        self.assertIn(status, (302, 303))
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(headers["location"]).query)["code"][0]
        status, _, body = self.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token", form={"grant_type": "authorization_code", "code": code, "client_id": "login-app", "redirect_uri": CALLBACK, "code_verifier": verifier})
        self.assertEqual(status, 200)
        return self.verify(json.loads(body)["access_token"])


if __name__ == "__main__":
    unittest.main()
