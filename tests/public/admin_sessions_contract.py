"""Admin session management compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/admin-session-observations.json.
Session representations have no `ipAddress` here, since client addresses are
not recorded.
"""

import json
import pathlib
import secrets
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/admin-session-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


class AdminSessionsContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.base = f"/admin/realms/{self.realm}"
        for name in ("first-app", "second-app"):
            self.assertEqual(self.call("POST", self.base + "/clients", {"clientId": name, "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        self.ids = {item["clientId"]: item["id"] for item in json.loads(self.call("GET", self.base + "/clients")[2])}
        self.user = self.call("POST", self.base + "/users", {"username": "reference-user", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "reference-user@example.invalid"})[1]["location"].rsplit("/", 1)[1]
        self.password = secrets.token_urlsafe(30)
        self.call("PUT", f"{self.base}/users/{self.user}/reset-password", {"type": "password", "value": self.password})

    def login(self, client):
        return self.browser_login(self.realm, client, CALLBACK, "reference-user", self.password)

    def shape(self, label, response):
        status, _, body = response
        parsed = json.loads(body) if body else None
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        if "count" in expected:
            self.assertEqual(len(parsed), expected["count"], label)
            fields = sorted({field for item in parsed for field in item})
            self.assertEqual(fields, [field for field in expected["item_fields"] if field != "ipAddress"], label)
            self.assertEqual(sorted(sorted(item.get("clients", {}).values()) for item in parsed), expected["clients"], label)
            self.assertEqual(sorted([item.get("clientId"), item.get("active"), item.get("offline")] for item in parsed if "active" in item), expected["stats"], label)
        if "body" in expected:
            self.assertEqual(parsed, expected["body"], label)

    def refresh(self, label, tokens, client):
        status, _, body = self.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token", form={"grant_type": "refresh_token", "client_id": client, "refresh_token": tokens["refresh_token"]})
        self.assertEqual({"status": status, "error": json.loads(body).get("error")}, REFERENCE[label], label)

    def shared_session(self):
        """Signs in to both clients in one session, then once more alone."""
        first, jar = self.browser_session(self.realm, "first-app", CALLBACK, "reference-user", self.password)
        second = self.sso_login(self.realm, "second-app", CALLBACK, jar)
        other = self.login("first-app")
        return first, second, other

    def test_listing(self):
        self.shared_session()
        self.shape("user/sessions", self.call("GET", f"{self.base}/users/{self.user}/sessions"))
        self.shape("client/user-sessions", self.call("GET", f"{self.base}/clients/{self.ids['first-app']}/user-sessions"))
        self.shape("client/session-count", self.call("GET", f"{self.base}/clients/{self.ids['first-app']}/session-count"))
        self.shape("client-session-stats", self.call("GET", self.base + "/client-session-stats"))

    def test_ending_a_shared_session(self):
        first, jar = self.browser_session(self.realm, "first-app", CALLBACK, "reference-user", self.password)
        second = self.sso_login(self.realm, "second-app", CALLBACK, jar)
        shared = self.verify(first["access_token"])["sid"]
        status, _, body = self.call("DELETE", f"{self.base}/sessions/{shared}")
        self.assertEqual({"status": status, "empty_body": not body}, REFERENCE["delete-session"])
        self.refresh("refresh/deleted-first", first, "first-app")
        self.refresh("refresh/deleted-second", second, "second-app")
        status, _, body = self.call("DELETE", f"{self.base}/sessions/00000000-0000-0000-0000-000000000000")
        self.assertEqual({"status": status, "body": json.loads(body)}, REFERENCE["delete-session/unknown"])

    def test_ending_one_session_keeps_others(self):
        ended, other = self.login("first-app"), self.login("first-app")
        self.assertEqual(self.call("DELETE", f"{self.base}/sessions/{self.verify(ended['access_token'])['sid']}")[0], 204)
        self.refresh("refresh/other-session", other, "first-app")

    def test_ending_user_sessions(self):
        other = self.login("first-app")
        status, _, body = self.call("POST", f"{self.base}/users/{self.user}/logout")
        self.assertEqual({"status": status, "empty_body": not body}, REFERENCE["user-logout"])
        self.refresh("refresh/after-user-logout", other, "first-app")
        self.shape("user/sessions-after", self.call("GET", f"{self.base}/users/{self.user}/sessions"))
        status, _, body = self.call("POST", self.base + "/users/00000000-0000-0000-0000-000000000000/logout")
        self.assertEqual({"status": status, "body": json.loads(body)}, REFERENCE["user-logout/unknown"])

    def test_ending_realm_sessions(self):
        again = self.login("first-app")
        self.shape("logout-all", self.call("POST", self.base + "/logout-all"))
        self.refresh("refresh/after-logout-all", again, "first-app")


if __name__ == "__main__":
    unittest.main()
