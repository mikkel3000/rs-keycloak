"""Client updates compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/admin-client-update-observations.json.
The other-id case carries `enabled` instead of the reference's `description`,
which this server does not model.
"""

import json
import pathlib
import secrets
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/admin-client-update-observations.json").read_text()
)["observations"]
COMPARED = ["clientId", "enabled", "publicClient", "serviceAccountsEnabled", "standardFlowEnabled", "redirectUris", "webOrigins", "bearerOnly"]


class AdminClientUpdateContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.base = f"/admin/realms/{self.realm}/clients"
        self.secret, self.other_secret = secrets.token_urlsafe(40), secrets.token_urlsafe(40)
        status, headers, _ = self.call("POST", self.base, {"clientId": "app", "secret": self.secret, "serviceAccountsEnabled": True, "redirectUris": ["https://app.example.invalid/cb"]})
        self.assertEqual(status, 201)
        self.app = f"{self.base}/{headers['location'].rsplit('/', 1)[1]}"
        self.assertEqual(self.call("POST", self.base, {"clientId": "taken", "publicClient": True})[0], 201)

    def case(self, response, label):
        status, _, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        self.assertEqual(not body, expected["empty_body"], label)
        parsed = json.loads(body) if body else None
        for key in COMPARED + ["error", "error_description"]:
            if key in expected.get("body", {}):
                self.assertEqual(parsed.get(key), expected["body"][key], f"{label}: {key}")
        if "has_secret" in expected and status == 200:
            self.assertEqual(bool(parsed.get("secret") or parsed.get("value")), expected["has_secret"], label)

    def grant(self, label, client_id, client_secret):
        status, _, body = self.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token", form={"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret})
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        parsed = json.loads(body)
        self.assertEqual({key: parsed[key] for key in ("error", "error_description") if key in parsed}, expected["body"], label)

    def test_partial_updates_take_effect(self):
        self.grant("grant/before", "app", self.secret)
        self.case(self.call("PUT", self.app, {"enabled": False}), "update/partial-disable")
        self.case(self.call("GET", self.app), "get/after-disable")
        self.grant("grant/disabled", "app", self.secret)
        self.case(self.call("PUT", self.app, {"enabled": True}), "update/enable")
        self.case(self.call("PUT", self.app, {"redirectUris": ["https://app.example.invalid/other"], "webOrigins": ["https://app.example.invalid"]}), "update/redirects")
        self.case(self.call("GET", self.app), "get/after-redirects")
        self.case(self.call("PUT", self.app, {"secret": self.other_secret}), "update/secret")
        self.grant("grant/old-secret", "app", self.secret)
        self.grant("grant/new-secret", "app", self.other_secret)
        self.case(self.call("PUT", self.app, {"clientId": "renamed"}), "update/rename")
        self.case(self.call("GET", self.app), "get/after-rename")
        self.grant("grant/renamed", "renamed", self.other_secret)
        account = json.loads(self.call("GET", f"{self.app}/service-account-user")[2])
        self.assertEqual(account["username"], "service-account-renamed")

    def reach_renamed_state(self):
        """Applies the earlier reference updates that later cases build on."""
        update = {"clientId": "renamed", "secret": self.other_secret, "redirectUris": ["https://app.example.invalid/other"], "webOrigins": ["https://app.example.invalid"]}
        self.assertEqual(self.call("PUT", self.app, update)[0], 204)

    def test_errors_and_ignored_id(self):
        self.reach_renamed_state()
        self.case(self.call("PUT", self.app, {"clientId": "taken"}), "update/duplicate-client-id")
        self.case(self.call("PUT", self.app, {"id": "00000000-0000-0000-0000-000000000000", "enabled": True}), "update/other-id-in-body")
        self.case(self.call("GET", self.app), "get/after-other-id")
        self.case(self.call("PUT", f"{self.base}/00000000-0000-0000-0000-000000000000", {"enabled": True}), "update/unknown")
        self.case(self.call("PUT", self.app, raw="{"), "update/malformed")
        self.case(self.call("PUT", self.app, {"enabled": False}, token=False), "update/no-token")

    def test_flows_and_client_type(self):
        self.reach_renamed_state()
        self.case(self.call("PUT", self.app, {"standardFlowEnabled": False, "serviceAccountsEnabled": False, "consentRequired": True}), "update/flows")
        self.case(self.call("GET", self.app), "get/after-flows")
        self.grant("grant/no-service-account", "renamed", self.other_secret)
        self.case(self.call("PUT", self.app, {"publicClient": True}), "update/to-public")
        self.case(self.call("GET", self.app), "get/after-public")
        self.case(self.call("PUT", self.app, {"publicClient": False}), "update/to-confidential")
        self.case(self.call("GET", self.app), "get/after-confidential")
        secret = json.loads(self.call("GET", f"{self.app}/client-secret")[2])["value"]
        self.assertNotEqual(secret, self.other_secret)


if __name__ == "__main__":
    unittest.main()
