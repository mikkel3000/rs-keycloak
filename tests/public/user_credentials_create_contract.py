"""User creation with credentials compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/user-credential-create-observations.json.
Known difference, listed in IMPLEMENTATION.md: an empty password is refused
with 400, where the reference stores a password credential without data.
"""

import json
import pathlib
import re
import secrets
import unittest
import urllib.parse

from fixture import AdminCase, b64


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/user-credential-create-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


class UserCredentialsCreateContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.base = f"/admin/realms/{self.realm}"
        self.password = secrets.token_urlsafe(24)
        self.assertEqual(self.call("POST", self.base + "/clients", {"clientId": "user-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)

    def create(self, label, username, credentials):
        status, headers, body = self.call("POST", self.base + "/users", {"username": username, "enabled": True, "firstName": "Reference", "lastName": "User", "email": f"{username}@example.invalid", "emailVerified": True, "credentials": credentials})
        expected = REFERENCE[label]
        self.assertEqual({"status": status, "body": json.loads(body) if body else None}, {key: expected[key] for key in ("status", "body")}, label)
        if status == 201:
            path = headers["location"].split("login.example.test", 1)[1]
            user = json.loads(self.call("GET", path)[2])
            stored = json.loads(self.call("GET", path + "/credentials")[2])
            self.assertEqual(sorted(user["requiredActions"]), expected["required_actions"], label)
            self.assertEqual(sorted(item["type"] for item in stored), expected["credential_types"], label)

    def login(self, label, username, password):
        query = urllib.parse.urlencode({"client_id": "user-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": b64(secrets.token_bytes(32)), "code_challenge_method": "S256"})
        status, headers, body = self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/auth?{query}")
        action = re.search(r'action="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        status, headers, body = self.request("POST", action, {"Cookie": headers["set-cookie"].split(";", 1)[0]}, {"username": username, "password": password})
        expected = REFERENCE[label]
        self.assertEqual("code=" in headers.get("location", ""), expected["code"], label)
        self.assertEqual(b"password-new" in body, expected["update_password_page"], label)

    def test_password(self):
        self.create("create/password", "plain-user", [{"type": "password", "value": self.password, "temporary": False}])
        self.login("login/password", "plain-user", self.password)

    def test_temporary_password(self):
        self.create("create/temporary", "temp-user", [{"type": "password", "value": self.password, "temporary": True}])
        self.login("login/temporary", "temp-user", self.password)

    def test_defaults_and_lists(self):
        self.create("create/default-temporary", "default-user", [{"type": "password", "value": self.password}])
        self.create("create/empty-list", "none-user", [])
        self.create("create/unknown-type", "otp-user", [{"type": "otp", "value": "123456"}])
        self.assertEqual(json.loads(self.call("GET", self.base + "/users?username=otp-user&exact=true")[2]), [])

    def test_last_password_wins(self):
        self.create("create/two-passwords", "two-user", [{"type": "password", "value": self.password, "temporary": False}, {"type": "password", "value": self.password + "x", "temporary": False}])
        self.login("login/two-passwords-first", "two-user", self.password)

    def test_empty_password_is_refused(self):
        status, _, _ = self.call("POST", self.base + "/users", {"username": "empty-user", "enabled": True, "credentials": [{"type": "password", "value": ""}]})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(self.call("GET", self.base + "/users?username=empty-user&exact=true")[2]), [])


if __name__ == "__main__":
    unittest.main()
