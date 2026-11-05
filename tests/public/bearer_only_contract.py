"""Bearer-only clients compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/bearer-only-observations.json. The
authorization request here carries PKCE, which this server requires before
it checks the client; the reference was observed without it.
"""

import base64
import json
import pathlib
import secrets
import unittest
import urllib.parse

from fixture import AdminCase, b64


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/bearer-only-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"
COMPARED = ["clientId", "enabled", "publicClient", "serviceAccountsEnabled", "bearerOnly", "protocol", "clientAuthenticatorType"]


class BearerOnlyContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.base = f"/admin/realms/{self.realm}"
        self.endpoint = f"/realms/{self.realm}/protocol/openid-connect"
        self.secret = secrets.token_urlsafe(40)

    def client(self, client_id):
        listed = json.loads(self.call("GET", f"{self.base}/clients?clientId={client_id}")[2])
        self.assertEqual(len(listed), 1, client_id)
        return listed[0]

    def assert_client(self, client, label):
        expected = REFERENCE[label]["body"]
        self.assertEqual({key: client.get(key) for key in COMPARED}, {key: expected[key] for key in COMPARED}, label)
        self.assertEqual(bool(client.get("secret")), REFERENCE[label]["has_secret"], label)

    def assert_oauth(self, response, label):
        status, _, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        self.assertEqual({key: value for key, value in json.loads(body).items() if key in ("active", "error", "error_description")}, expected["body"], label)

    def roles(self, client_id):
        return sorted(role["name"] for role in json.loads(self.call("GET", f"{self.base}/clients/{client_id}/roles")[2]))

    def composites(self, client_id, role):
        return sorted(item["name"] for item in json.loads(self.call("GET", f"{self.base}/clients/{client_id}/roles/{role}/composites")[2]))

    def test_management_builtins_and_roles(self):
        for name in ["broker", "realm-management", "security-admin-console"]:
            client = self.client(name)
            self.assert_client(client, "builtin/" + name)
            self.assertEqual(self.roles(client["id"]), REFERENCE["builtin/" + name]["roles"], name)
        management = self.client("realm-management")["id"]
        self.assertEqual(self.composites(management, "realm-admin"), REFERENCE["realm-admin/composites"])
        for role in ["view-users", "view-clients"]:
            self.assertEqual(self.composites(management, role), REFERENCE[f"composites/{role}"], role)

    def test_creation_variants(self):
        for label, payload in [
            ("bearer-only", {"clientId": "api", "bearerOnly": True, "secret": self.secret}),
            ("bearer-only-public", {"clientId": "api-public", "bearerOnly": True, "publicClient": True}),
            ("bearer-only-service-account", {"clientId": "api-service-account", "bearerOnly": True, "serviceAccountsEnabled": True}),
        ]:
            status, headers, _ = self.call("POST", f"{self.base}/clients", payload)
            self.assertEqual(status, REFERENCE["create/" + label]["status"], label)
            created = json.loads(self.call("GET", headers["location"].split("login.example.test", 1)[1])[2])
            self.assert_client(created, "get/" + label)

    def test_bearer_only_client_cannot_obtain_or_revoke_tokens(self):
        self.assertEqual(self.call("POST", f"{self.base}/clients", {"clientId": "api", "bearerOnly": True, "secret": self.secret})[0], 201)
        self.assertEqual(self.call("POST", f"{self.base}/clients", {"clientId": "user-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        query = urllib.parse.urlencode({
            "client_id": "api", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid",
            "code_challenge": b64(secrets.token_bytes(32)), "code_challenge_method": "S256", "state": "state",
        })
        status, headers, body = self.request("GET", f"{self.endpoint}/auth?{query}")
        expected = REFERENCE["authorize/bearer-only"]
        self.assertEqual((status, headers["content-type"].split(";")[0], b"earer" in body), (expected["status"], expected["content_type"].split(";")[0], expected["mentions_bearer_only"]))
        self.assertNotIn("location", headers)
        self.assert_oauth(self.request("POST", self.endpoint + "/token", form={"grant_type": "client_credentials", "client_id": "api", "client_secret": self.secret}), "token/client-credentials")
        password = secrets.token_urlsafe(30)
        location = self.call("POST", f"{self.base}/users", {"username": "reference-user", "enabled": True})[1]["location"]
        self.call("PUT", location.split("login.example.test", 1)[1] + "/reset-password", {"type": "password", "value": password})
        tokens = self.browser_login(self.realm, "user-app", CALLBACK, "reference-user", password)
        basic = lambda secret: {"Authorization": "Basic " + base64.b64encode(f"api:{secret}".encode()).decode()}
        self.assert_oauth(self.request("POST", self.endpoint + "/token/introspect", basic(self.secret), {"token": tokens["access_token"]}), "introspect/user-token")
        self.assert_oauth(self.request("POST", self.endpoint + "/token/introspect", basic("wrong"), {"token": tokens["access_token"]}), "introspect/wrong-secret")
        self.assert_oauth(self.request("POST", self.endpoint + "/revoke", basic(self.secret), {"token": tokens["refresh_token"]}), "revoke/bearer-only")
        refreshed = self.request("POST", self.endpoint + "/token", form={"grant_type": "refresh_token", "client_id": "user-app", "refresh_token": tokens["refresh_token"]})
        self.assertEqual(refreshed[0], 200, "refused revocation leaves the session")

    def test_secretless_builtin_cannot_authenticate(self):
        status, _, body = self.request("POST", self.endpoint + "/token", form={"grant_type": "client_credentials", "client_id": "realm-management", "client_secret": self.secret})
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"], "unauthorized_client")


if __name__ == "__main__":
    unittest.main()
