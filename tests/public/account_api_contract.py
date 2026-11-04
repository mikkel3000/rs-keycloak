"""Account REST API compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/account-api-observations.json. The
reference also accepts tokens from an ordinary client, so the contract signs
in through one; realms here have no built-in account-console client.
"""

import json
import pathlib
import secrets
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/account-api-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


def shape(response):
    status, headers, body = response
    parsed = json.loads(body) if body and "json" in headers.get("content-type", "") else None
    result = {"status": status, "www_authenticate": bool(headers.get("www-authenticate"))}
    if isinstance(parsed, dict):
        result["fields"] = sorted(parsed)
        result["body"] = {k: parsed[k] for k in ("username", "firstName", "lastName", "email", "emailVerified", "error", "errorMessage", "field") if k in parsed}
    elif isinstance(parsed, list):
        result["length"] = len(parsed)
        result["item_fields"] = sorted({f for item in parsed for f in item}) if parsed and isinstance(parsed[0], dict) else []
    return result


class AccountApiContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "plain-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        users = f"/admin/realms/{self.realm}/users"
        user = self.call("POST", users, {"username": "reference-user", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "reference@example.invalid", "emailVerified": True})[1]["location"].rsplit("/", 1)[1]
        self.call("POST", users, {"username": "other-user", "enabled": True, "email": "other@example.invalid"})
        password = secrets.token_urlsafe(30)
        self.call("PUT", f"{users}/{user}/reset-password", {"type": "password", "value": password})
        self.access = self.browser_login(self.realm, "plain-app", CALLBACK, "reference-user", password)["access_token"]
        self.api = f"/realms/{self.realm}/account"

    def get(self, path="", token=True):
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + self.access
        return self.request("GET", self.api + path, headers)

    def update(self, body):
        return self.request("POST", self.api, {"Authorization": "Bearer " + self.access, "Content-Type": "application/json"}, body=json.dumps(body))

    def test_profile_read_and_update(self):
        self.assertEqual(shape(self.get(token=False)), REFERENCE["profile/no-token"])
        self.assertEqual(shape(self.get()), REFERENCE["profile/plain-client-token"])
        self.assertEqual(shape(self.update({"username": "reference-user", "firstName": "Changed", "lastName": "Person", "email": "reference@example.invalid"})), REFERENCE["profile/update"])
        self.assertEqual(shape(self.get()), REFERENCE["profile/after-update"])
        self.assertEqual(shape(self.update({"username": "reference-user", "firstName": "Changed", "lastName": "Person", "email": "other@example.invalid"})), REFERENCE["profile/update-taken-email"])
        self.assertEqual(shape(self.update({"username": "reference-user", "firstName": "", "lastName": "Person", "email": "reference@example.invalid"})), REFERENCE["profile/update-missing-first-name"])

    def test_credentials_and_sessions(self):
        self.assertEqual(shape(self.get("/credentials")), REFERENCE["credentials/list"])
        sessions = self.get("/sessions")
        observed = shape(sessions)
        expected = REFERENCE["sessions/list"]
        # The reference user had two sessions (account-console and plain-app).
        self.assertEqual((observed["status"], observed["item_fields"]), (expected["status"], expected["item_fields"]))
        listed = json.loads(sessions[2])
        self.assertEqual([session["current"] for session in listed], [True])
        status, _, _ = self.request("DELETE", f"{self.api}/sessions/{listed[0]['id']}", {"Authorization": "Bearer " + self.access})
        self.assertEqual(status, 204)
        self.assertEqual(self.get()[0], 401)


if __name__ == "__main__":
    unittest.main()
