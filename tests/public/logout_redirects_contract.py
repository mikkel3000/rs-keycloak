"""Post-logout redirect matching compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/logout-redirect-observations.json;
BASE stands in for the reference's server base in registered URIs.
"""

import json
import pathlib
import secrets
import unittest
import urllib.parse

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/logout-redirect-observations.json").read_text()
)["observations"]
BASE = "https://app.example.test"
CALLBACK = BASE + "/callback"


class LogoutRedirectsContract(AdminCase):
    def setUp(self):
        super().setUp()
        clients = f"/admin/realms/{self.realm}/clients"
        self.assertEqual(self.call("POST", clients, {"clientId": "plus-app", "publicClient": True, "redirectUris": [CALLBACK, BASE + "/app/*"], "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "+"}})[0], 201)
        self.assertEqual(self.call("POST", clients, {"clientId": "explicit-app", "publicClient": True, "redirectUris": [CALLBACK], "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": BASE + "/out/*"}})[0], 201)
        user = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "reference-user", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "reference-user@example.invalid"})[1]["location"].rsplit("/", 1)[1]
        self.password = secrets.token_urlsafe(32)
        self.call("PUT", f"/admin/realms/{self.realm}/users/{user}/reset-password", {"type": "password", "value": self.password})

    def check(self, label, client, redirect):
        tokens = self.browser_login(self.realm, client, CALLBACK, "reference-user", self.password)
        params = urllib.parse.urlencode({"id_token_hint": tokens["id_token"], "post_logout_redirect_uri": redirect, "state": "state"})
        status, headers, _ = self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/logout?{params}")
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        self.assertEqual(headers.get("content-type", "").startswith("text/html"), expected["html"], label)
        if expected.get("location"):
            location = urllib.parse.urlsplit(headers["location"])
            self.assertEqual(location.scheme + "://" + location.netloc + location.path, expected["location"].replace("{base}", BASE), label)
            self.assertEqual(sorted(urllib.parse.parse_qs(location.query)), expected["location_params"], label)
        else:
            self.assertNotIn("location", headers, label)

    # One login per test keeps each case well under the time limit.
    def test_plus_exact_redirect(self):
        self.check("plus/exact-redirect", "plus-app", CALLBACK)

    def test_plus_wildcard_redirect(self):
        self.check("plus/wildcard-redirect", "plus-app", BASE + "/app/out")

    def test_plus_outside(self):
        self.check("plus/outside", "plus-app", BASE + "/elsewhere")

    def test_explicit_wildcard(self):
        self.check("explicit/wildcard", "explicit-app", BASE + "/out/done?x=1")

    def test_explicit_excludes_redirect_uris(self):
        self.check("explicit/redirect-uri", "explicit-app", CALLBACK)

    def test_explicit_dot_segment(self):
        self.check("explicit/dot-segment", "explicit-app", BASE + "/out/../elsewhere")

if __name__ == "__main__":
    unittest.main()
