"""User updates compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/admin-user-update-observations.json.
"""

import json
import pathlib
import secrets
import unittest

from fixture import AdminCase, class_per_test


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/admin-user-update-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


class AdminUserUpdateContract(AdminCase):
    def setUp(self):
        super().setUp()
        base = f"/admin/realms/{self.realm}"
        status, headers, _ = self.call("POST", base + "/users", {"username": "reference-user", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "reference@example.invalid", "emailVerified": True})
        self.assertEqual(status, 201)
        self.user = f"{base}/users/{headers['location'].rsplit('/', 1)[1]}"
        self.assertEqual(self.call("POST", base + "/users", {"username": "other-user", "enabled": True, "email": "other@example.invalid"})[0], 201)

    def case(self, response, label):
        status, _, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        self.assertEqual(not body, expected["empty_body"], label)
        if body:
            parsed = json.loads(body)
            self.assertEqual({key: parsed[key] for key in expected["body"] if key in parsed}, expected["body"], label)
            for key in ("firstName", "lastName", "email"):
                self.assertEqual(key in parsed, key in expected["body"], f"{label}: {key}")
            if "required_actions" in expected:
                self.assertEqual(sorted(parsed["requiredActions"]), expected["required_actions"], label)

    def test_profile_fields(self):
        for label, payload in [
            ("first-name", {"firstName": "Changed"}),
            ("email", {"email": "New@Example.invalid"}),
            ("email-verified", {"emailVerified": True}),
        ]:
            self.case(self.call("PUT", self.user, payload), "update/" + label)
            self.case(self.call("GET", self.user), "get/after-" + label)
        self.case(self.call("PUT", self.user, {"email": "other@example.invalid"}), "update/duplicate-email")
        self.case(self.call("PUT", self.user, {"username": "renamed-user"}), "update/username")
        self.case(self.call("GET", self.user), "get/after-username")
        self.case(self.call("PUT", self.user, {"username": "reference-user", "lastName": "Same"}), "update/same-username")
        self.case(self.call("GET", self.user), "get/after-same-username")
        self.case(self.call("PUT", self.user, {"firstName": ""}), "update/clear-first-name")
        self.case(self.call("GET", self.user), "get/after-clear")
        self.case(self.call("PUT", self.user, {"requiredActions": ["UPDATE_PASSWORD"]}), "update/required-actions")
        self.case(self.call("GET", self.user), "get/after-required-actions")

    def reach_reference_state(self):
        """Applies the earlier reference updates that later cases build on."""
        self.assertEqual(self.call("PUT", self.user, {"email": "new@example.invalid", "firstName": "", "lastName": "Same"})[0], 204)

    def login_fixture(self):
        """Adds a public client and a password, returning the password."""
        self.assertEqual(self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "user-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        password = secrets.token_urlsafe(30)
        self.assertEqual(self.call("PUT", self.user + "/reset-password", {"type": "password", "value": password})[0], 204)
        return password

    def test_disabling_stops_login(self):
        self.reach_reference_state()
        password = self.login_fixture()
        self.case(self.call("PUT", self.user, {"enabled": False}), "update/disable")
        self.case(self.call("GET", self.user), "get/after-disable")
        self.assertFalse(REFERENCE["login/disabled"]["completed"])
        with self.assertRaises(AssertionError):
            self.browser_login(self.realm, "user-app", CALLBACK, "reference-user", password)

    def test_enabling_restores_login(self):
        self.reach_reference_state()
        password = self.login_fixture()
        self.assertEqual(self.call("PUT", self.user, {"enabled": False})[0], 204)
        self.case(self.call("PUT", self.user, {"enabled": True, "firstName": "Restored"}), "update/enable")
        self.assertTrue(REFERENCE["login/enabled"]["completed"])
        self.assertTrue(self.browser_login(self.realm, "user-app", CALLBACK, "reference-user", password)["access_token"])

    def test_errors_and_ignored_id(self):
        self.reach_reference_state()
        self.assertEqual(self.call("PUT", self.user, {"firstName": "Restored"})[0], 204)
        self.case(self.call("PUT", self.user, {"id": "00000000-0000-0000-0000-000000000000", "lastName": "Body"}), "update/other-id-in-body")
        self.case(self.call("GET", self.user), "get/after-other-id")
        self.case(self.call("PUT", f"/admin/realms/{self.realm}/users/00000000-0000-0000-0000-000000000000", {"firstName": "x"}), "update/unknown")
        self.case(self.call("PUT", self.user, raw="{"), "update/malformed")
        self.case(self.call("PUT", self.user, {"email": "not-an-email"}), "update/invalid-email")


class_per_test(AdminUserUpdateContract, globals())

if __name__ == "__main__":
    unittest.main()
