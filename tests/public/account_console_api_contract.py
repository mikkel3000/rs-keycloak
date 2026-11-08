"""Account console API routes compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/account-console-api-observations.json.
Known difference, listed in IMPLEMENTATION.md: user agents and addresses
are not recorded, so every session belongs to one unknown device and has no
`ipAddress`, and applications have no `clientName` of their own.
"""

import json
import pathlib
import secrets
import unittest

from fixture import ISSUER_BASE, AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/account-console-api-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


class AccountConsoleApiContract(AdminCase):
    def setUp(self):
        super().setUp()
        base = f"/admin/realms/{self.realm}"
        for name in ("plain-app", "unused-app"):
            self.assertEqual(self.call("POST", base + "/clients", {"clientId": name, "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        user = self.call("POST", base + "/users", {"username": "reference-user", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "reference-user@example.invalid"})[1]["location"].rsplit("/", 1)[1]
        password = secrets.token_urlsafe(30)
        self.call("PUT", f"{base}/users/{user}/reset-password", {"type": "password", "value": password})
        self.account = self.browser_login(self.realm, "account-console", f"{ISSUER_BASE}/realms/{self.realm}/account/", "reference-user", password)
        self.plain = self.browser_login(self.realm, "plain-app", CALLBACK, "reference-user", password, scope="openid offline_access")
        self.api = f"/realms/{self.realm}/account"
        self.headers = {"Authorization": "Bearer " + self.account["access_token"], "Accept": "application/json"}

    def get(self, path):
        status, _, body = self.request("GET", self.api + path, self.headers)
        return status, json.loads(body)

    def refresh(self, label, client, tokens):
        status, _, body = self.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token", form={"grant_type": "refresh_token", "client_id": client, "refresh_token": tokens["refresh_token"]})
        self.assertEqual({"status": status, "error": json.loads(body).get("error")}, REFERENCE[label], label)

    def test_applications_and_devices(self):
        status, listed = self.get("/applications")
        expected = REFERENCE["applications"]
        self.assertEqual(status, expected["status"])
        self.assertEqual(sorted([item["clientId"], item.get("inUse"), item.get("offlineAccess"), item.get("userConsentRequired"), "effectiveUrl" in item] for item in listed), expected["apps"])
        self.assertEqual(sorted({field for item in listed for field in item}), expected["fields"])
        status, devices = self.get("/sessions/devices")
        expected = REFERENCE["devices"]
        sessions = [session for device in devices for session in device["sessions"]]
        self.assertEqual((status, len(devices), len(sessions)), (expected["status"], expected["count"], expected["sessions"]))
        self.assertEqual(sorted({field for device in devices for field in device}), expected["device_fields"])
        self.assertEqual(sorted({field for session in sessions for field in session}), expected["session_fields"])
        self.assertEqual(sorted(bool(session["current"]) for session in sessions), expected["current"])
        self.assertEqual(sorted(sorted(client["clientId"] for client in session["clients"]) for session in sessions), expected["clients"])

    def test_ending_other_sessions(self):
        status, _, body = self.request("DELETE", self.api + "/sessions", self.headers)
        self.assertEqual({"status": status, "empty_body": not body}, REFERENCE["sessions/delete-others"])
        self.refresh("refresh/current-after-delete", "account-console", self.account)
        # The other session's tokens end, the offline one included.
        self.refresh("refresh/other-online-after-delete", "plain-app", self.plain)

    def test_revoking_an_application(self):
        status, _, body = self.request("DELETE", self.api + "/applications/plain-app/consent", self.headers)
        self.assertEqual({"status": status, "empty_body": not body}, REFERENCE["applications/revoke-consent"])
        status, _, body = self.request("DELETE", self.api + "/applications/missing-app/consent", self.headers)
        self.assertEqual({"status": status, "body": json.loads(body)}, REFERENCE["applications/revoke-unknown"])
        _, listed = self.get("/applications")
        self.assertEqual({"apps": sorted([item["clientId"], item.get("inUse"), item.get("offlineAccess")] for item in listed)}, REFERENCE["applications/after-revoke"])


if __name__ == "__main__":
    unittest.main()
