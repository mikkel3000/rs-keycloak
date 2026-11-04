"""OIDC logout compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/logout-observations.json.
"""

import json
import pathlib
import secrets
import unittest
import urllib.parse

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/logout-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


class LogoutContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.endpoint = f"/realms/{self.realm}/protocol/openid-connect"
        clients = f"/admin/realms/{self.realm}/clients"
        self.assertEqual(self.call("POST", clients, {"clientId": "logout-app", "publicClient": True, "redirectUris": [CALLBACK], "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": CALLBACK + "/logged-out"}})[0], 201)
        self.assertEqual(self.call("POST", clients, {"clientId": "other-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        user = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "reference-user", "enabled": True})[1]["location"].rsplit("/", 1)[1]
        self.password = secrets.token_urlsafe(32)
        self.call("PUT", f"/admin/realms/{self.realm}/users/{user}/reset-password", {"type": "password", "value": self.password})

    def login(self):
        return self.browser_login(self.realm, "logout-app", CALLBACK, "reference-user", self.password)

    def assert_case(self, response, label):
        status, headers, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        self.assertEqual(headers.get("cache-control"), expected["cache_control"], label)
        if expected["body"]:
            self.assertEqual({k: v for k, v in json.loads(body).items() if k in expected["body"]}, expected["body"], label)
        if "html" in expected:
            self.assertEqual(headers.get("content-type", "").startswith("text/html"), expected["html"], label)
        if expected.get("location"):
            location = urllib.parse.urlsplit(headers["location"])
            self.assertEqual(location.scheme + "://" + location.netloc + location.path, CALLBACK + "/logged-out", label)
            self.assertEqual(sorted(urllib.parse.parse_qs(location.query)), expected["location_params"], label)

    def assert_ended(self, tokens, label):
        status, _, body = self.request("POST", self.endpoint + "/token", form={"grant_type": "refresh_token", "client_id": "logout-app", "refresh_token": tokens["refresh_token"]})
        self.assertEqual(status, REFERENCE[label + "/refresh"]["status"], label)
        self.assertEqual(json.loads(body)["error"], REFERENCE[label + "/refresh"]["body"]["error"], label)
        status, headers, _ = self.request("GET", self.endpoint + "/userinfo", {"Authorization": "Bearer " + tokens["access_token"]})
        expected = REFERENCE[label + "/userinfo"]
        self.assertEqual(status, expected["status"], label)
        self.assertEqual(headers.get("www-authenticate"), expected["www_authenticate"].replace("{realm}", self.realm), label)

    def post(self, form):
        return self.request("POST", self.endpoint + "/logout", form=form)

    def get(self, params):
        return self.request("GET", self.endpoint + "/logout?" + urllib.parse.urlencode(params))

    def test_refresh_token_logout(self):
        tokens = self.login()
        self.assert_case(self.post({"client_id": "logout-app"}), "post/missing-refresh-token")
        self.assert_case(self.post({"refresh_token": tokens["refresh_token"]}), "post/no-client")
        self.assert_case(self.post({"client_id": "other-app", "refresh_token": tokens["refresh_token"]}), "post/other-client")
        self.assert_case(self.post({"client_id": "logout-app", "refresh_token": tokens["refresh_token"]}), "post/success")
        self.assert_ended(tokens, "post/after")
        self.assert_case(self.post({"client_id": "logout-app", "refresh_token": tokens["refresh_token"]}), "post/repeat")

    def test_browser_logout_with_redirect(self):
        tokens = self.login()
        self.assert_case(self.get({"id_token_hint": tokens["id_token"], "post_logout_redirect_uri": CALLBACK + "/elsewhere"}), "get/unregistered-redirect")
        self.assert_case(self.get({"post_logout_redirect_uri": CALLBACK + "/logged-out", "client_id": "logout-app"}), "get/no-hint")
        self.assert_case(self.get({"id_token_hint": "not-a-token", "post_logout_redirect_uri": CALLBACK + "/logged-out"}), "get/invalid-hint")
        self.assert_case(self.get({"id_token_hint": tokens["id_token"], "post_logout_redirect_uri": CALLBACK + "/logged-out", "state": "logout-state"}), "get/redirect")
        self.assert_ended(tokens, "get/after")

    def test_browser_logout_without_redirect(self):
        tokens = self.login()
        self.assert_case(self.get({"id_token_hint": tokens["id_token"]}), "get/hint-without-redirect")
        self.assert_ended(tokens, "get/without-redirect-after")


if __name__ == "__main__":
    unittest.main()
