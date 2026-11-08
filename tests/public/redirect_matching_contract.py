"""Redirect URI matching compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/redirect-matching-observations.json.
The server base here is the fixture issuer base rather than the reference's
loopback address, so the account-console cases use it, and the other-host
case keeps the reference's http host.
"""

import hashlib
import json
import pathlib
import secrets
import unittest
import urllib.parse

from fixture import ISSUER_BASE, AdminCase, b64


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/redirect-matching-observations.json").read_text()
)["observations"]


class RedirectMatchingContract(AdminCase):
    def setUp(self):
        super().setUp()
        status, _, body = self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "rooted-app", "publicClient": True, "rootUrl": "https://app.example.invalid", "redirectUris": ["/cb", "https://exact.example.invalid/*", "https://query.example.invalid/cb?x=1"]})
        self.assertEqual(status, 201, body)

    def authorize(self, client, redirect):
        query = urllib.parse.urlencode({"client_id": client, "redirect_uri": redirect, "response_type": "code", "scope": "openid", "state": "state", "code_challenge": b64(hashlib.sha256(secrets.token_bytes(32)).digest()), "code_challenge_method": "S256"})
        status, _, body = self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/auth?{query}")
        return status, b'name="username"' in body

    def check(self, label, client, redirect):
        expected = REFERENCE[label]
        self.assertEqual(self.authorize(client, redirect), (expected["status"], expected["login_form"]), label)

    def test_account_console(self):
        account = f"{ISSUER_BASE}/realms/{self.realm}/account"
        for label, redirect in [
            ("base", account + "/"),
            ("deep", account + "/x/y?z=1"),
            ("no-slash", account),
            ("other-path", f"{ISSUER_BASE}/realms/{self.realm}/other"),
            ("other-host", f"http://evil.example.invalid/realms/{self.realm}/account/"),
            ("dot-segment", account + "/../other"),
        ]:
            self.check("account-console/" + label, "account-console", redirect)

    def test_rooted_client(self):
        for label, redirect in [
            ("relative", "https://app.example.invalid/cb"),
            ("relative-other-host", ISSUER_BASE + "/cb"),
            ("wildcard", "https://exact.example.invalid/any/path"),
            ("wildcard-root", "https://exact.example.invalid/"),
            ("wildcard-bare", "https://exact.example.invalid"),
            ("wildcard-query", "https://exact.example.invalid/p?q=1"),
            ("wildcard-userinfo", "https://user@exact.example.invalid/p"),
            ("wildcard-other-port", "https://exact.example.invalid:8443/p"),
            ("exact-query", "https://query.example.invalid/cb?x=1"),
            ("exact-query-other", "https://query.example.invalid/cb?x=2"),
            ("exact-query-missing", "https://query.example.invalid/cb"),
            ("fragment", "https://app.example.invalid/cb#f"),
            ("case", "https://APP.example.invalid/cb"),
        ]:
            self.check("rooted/" + label, "rooted-app", redirect)

    def test_account_console_signs_in(self):
        password = secrets.token_urlsafe(30)
        location = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "console-user", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "console-user@example.invalid"})[1]["location"]
        self.call("PUT", location.split(ISSUER_BASE, 1)[1] + "/reset-password", {"type": "password", "value": password})
        # Any path below the account page matches the console's wildcard.
        redirect = f"{ISSUER_BASE}/realms/{self.realm}/account/personal-info"
        tokens = self.browser_login(self.realm, "account-console", redirect, "console-user", password)
        self.assertEqual(self.verify(tokens["access_token"])["azp"], "account-console")

    def test_registration_rules(self):
        clients = f"/admin/realms/{self.realm}/clients"
        for bad in [
            {"clientId": "no-root", "publicClient": True, "redirectUris": ["/cb"]},
            {"clientId": "inner-wildcard", "publicClient": True, "redirectUris": ["https://*.example.invalid/cb"]},
            {"clientId": "bad-root", "publicClient": True, "rootUrl": "http://app.example.invalid", "redirectUris": ["/cb"]},
        ]:
            self.assertEqual(self.call("POST", clients, bad)[0], 400, bad["clientId"])
        rooted = json.loads(self.call("GET", clients + "?clientId=rooted-app")[2])[0]
        self.assertEqual(rooted["rootUrl"], "https://app.example.invalid")
        console = json.loads(self.call("GET", clients + "?clientId=account-console")[2])[0]
        self.assertEqual((console["rootUrl"], console["baseUrl"], console["redirectUris"]), ("${authBaseUrl}", f"/realms/{self.realm}/account/", [f"/realms/{self.realm}/account/*"]))


if __name__ == "__main__":
    unittest.main()
