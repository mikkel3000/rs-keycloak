"""Required action administration compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/required-action-admin-observations.json.
Only the four actions this server performs are listed, so the listing is
compared with those rows of the reference's.
"""

import json
import pathlib
import secrets
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/required-action-admin-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"
MODELLED = {"CONFIGURE_TOTP", "UPDATE_PASSWORD", "UPDATE_PROFILE", "VERIFY_EMAIL"}


class RequiredActionsAdminContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.actions = f"/admin/realms/{self.realm}/authentication/required-actions"

    def test_listing_and_reading(self):
        status, _, body = self.call("GET", self.actions)
        listed = json.loads(body)
        expected = REFERENCE["list"]
        self.assertEqual(status, expected["status"])
        self.assertEqual(sorted({field for item in listed for field in item}), expected["fields"])
        self.assertEqual([[item["alias"], item["name"], item["providerId"], item["enabled"], item["defaultAction"], item["priority"]] for item in listed], [row for row in expected["actions"] if row[0] in MODELLED])
        status, _, body = self.call("GET", self.actions + "/UPDATE_PASSWORD")
        parsed = json.loads(body)
        self.assertEqual({"status": status, "body": {key: parsed.get(key) for key in REFERENCE["get"]["body"]}}, REFERENCE["get"])
        status, _, body = self.call("GET", self.actions + "/MISSING")
        self.assertEqual({"status": status, "body": json.loads(body)}, REFERENCE["get/unknown"])

    def test_disabled_action_is_skipped_at_login(self):
        self.assertEqual(self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "user-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        location = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "reference-user", "enabled": True, "requiredActions": ["UPDATE_PASSWORD"]})[1]["location"]
        user = location.split("login.example.test", 1)[1]
        password = secrets.token_urlsafe(30)
        self.call("PUT", user + "/reset-password", {"type": "password", "value": password, "temporary": False})
        self.assertEqual(self.call("PUT", user, {"requiredActions": ["UPDATE_PASSWORD"]})[0], 204)
        current = json.loads(self.call("GET", self.actions + "/UPDATE_PASSWORD")[2])
        status, _, body = self.call("PUT", self.actions + "/UPDATE_PASSWORD", dict(current, enabled=False))
        self.assertEqual({"status": status, "empty_body": not body}, REFERENCE["disable"])
        self.assertEqual({"enabled": json.loads(self.call("GET", self.actions + "/UPDATE_PASSWORD")[2])["enabled"]}, REFERENCE["get/after-disable"])
        tokens = self.browser_login(self.realm, "user-app", CALLBACK, "reference-user", password)
        self.assertEqual({"completed": bool(tokens.get("access_token"))}, REFERENCE["login/action-disabled"])
        self.assertEqual({"actions": json.loads(self.call("GET", user)[2])["requiredActions"]}, REFERENCE["user/required-actions"])

    def test_default_action_for_new_users(self):
        current = json.loads(self.call("GET", self.actions + "/UPDATE_PASSWORD")[2])
        self.assertEqual({"status": self.call("PUT", self.actions + "/UPDATE_PASSWORD", dict(current, defaultAction=True))[0]}, REFERENCE["default-action"])
        location = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "new-user", "enabled": True})[1]["location"]
        created = json.loads(self.call("GET", location.split("login.example.test", 1)[1])[2])
        self.assertEqual({"actions": created["requiredActions"]}, REFERENCE["new-user/required-actions"])

    def test_errors(self):
        status, _, body = self.call("PUT", self.actions + "/UPDATE_PASSWORD", {"enabled": "yes"})
        self.assertEqual({"status": status, "body": json.loads(body)}, REFERENCE["update/malformed"])
        status, _, body = self.call("PUT", self.actions + "/MISSING", {"alias": "MISSING", "enabled": True})
        self.assertEqual({"status": status, "body": json.loads(body)}, REFERENCE["update/unknown"])
        self.assertEqual(self.call("PUT", self.actions + "/UPDATE_PASSWORD", {"priority": 1})[0], 400)


if __name__ == "__main__":
    unittest.main()
