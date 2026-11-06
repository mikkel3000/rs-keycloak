"""Realm display name and token lifespan compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/realm-setting-observations.json.
Known difference, listed in IMPLEMENTATION.md: zero and negative lifespans
are refused here, where the reference stores them.
"""

import base64
import json
import pathlib
import secrets
import unittest
import urllib.parse

from fixture import AdminCase, b64


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/realm-setting-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"
MODELLED = ("displayName", "accessTokenLifespan")


class RealmSettingsContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.base = f"/admin/realms/{self.realm}"
        self.secret = secrets.token_urlsafe(40)
        self.assertEqual(self.call("POST", self.base + "/clients", {"clientId": "service-app", "secret": self.secret, "serviceAccountsEnabled": True, "standardFlowEnabled": False})[0], 201)

    def settings(self, label):
        parsed = json.loads(self.call("GET", self.base)[2])
        self.assertEqual({key: parsed.get(key) for key in MODELLED}, {key: REFERENCE[label][key] for key in MODELLED}, label)

    def update(self, label, payload):
        status, _, body = self.call("PUT", self.base, payload)
        self.assertEqual({"status": status, "body": json.loads(body) if body else None}, REFERENCE[label], label)

    def service_lifetime(self):
        status, _, body = self.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token", form={"grant_type": "client_credentials", "client_id": "service-app", "client_secret": self.secret})
        self.assertEqual(status, 200)
        tokens = json.loads(body)
        claims = self.verify(tokens["access_token"])
        return tokens["expires_in"], claims["exp"] - claims["iat"]

    def code_lifetimes(self):
        self.assertEqual(self.call("POST", self.base + "/clients", {"clientId": "user-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        password = secrets.token_urlsafe(30)
        user = self.call("POST", self.base + "/users", {"username": "reference-user", "enabled": True})[1]["location"].rsplit("/", 1)[1]
        self.call("PUT", f"{self.base}/users/{user}/reset-password", {"type": "password", "value": password})
        tokens = self.browser_login(self.realm, "user-app", CALLBACK, "reference-user", password)
        access = self.verify(tokens["access_token"])
        id_payload = tokens["id_token"].split(".")[1]
        identity = json.loads(base64.urlsafe_b64decode(id_payload + "=" * (-len(id_payload) % 4)))
        return tokens["expires_in"], access["exp"] - access["iat"], identity["exp"] - identity["iat"]

    def test_defaults(self):
        self.settings("defaults")
        expected = REFERENCE["lifetimes/defaults"]
        self.assertEqual(self.service_lifetime(), (expected["service_expires_in"], expected["service_lifetime"]))

    def test_update_sets_token_lifetimes(self):
        self.update("update/settings", {"displayName": "Shown Realm", "accessTokenLifespan": 60})
        self.settings("after-update")
        expected = REFERENCE["lifetimes/after-update"]
        self.assertEqual(self.service_lifetime(), (expected["service_expires_in"], expected["service_lifetime"]))
        self.assertEqual(self.code_lifetimes(), (expected["code_expires_in"], expected["access_lifetime"], expected["id_lifetime"]))

    def test_login_page_shows_the_display_name(self):
        self.assertEqual(self.call("POST", self.base + "/clients", {"clientId": "user-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        query = urllib.parse.urlencode({"client_id": "user-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "state", "code_challenge": b64(secrets.token_bytes(32)), "code_challenge_method": "S256"})
        page = lambda: self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/auth?{query}")[2].decode()
        self.assertEqual("Shown Realm" in page(), REFERENCE["login-page/default"]["shows_display_name"])
        self.assertEqual(self.call("PUT", self.base, {"displayName": "Shown Realm"})[0], 204)
        self.assertEqual("Shown Realm" in page(), REFERENCE["login-page/display-name"]["shows_display_name"])

    def test_invalid_and_cleared_values(self):
        self.assertEqual(self.call("PUT", self.base, {"displayName": "Shown Realm", "accessTokenLifespan": 60})[0], 204)
        for payload in ({"accessTokenLifespan": 0}, {"accessTokenLifespan": -5}):
            self.assertEqual(self.call("PUT", self.base, payload)[0], 400, payload)
        self.update("update/text-lifespan", {"accessTokenLifespan": "abc"})
        self.update("update/clear-display-name", {"displayName": ""})
        parsed = json.loads(self.call("GET", self.base)[2])
        self.assertEqual((parsed["displayName"], parsed["accessTokenLifespan"]), (REFERENCE["after-clear"]["displayName"], 60))


if __name__ == "__main__":
    unittest.main()
