"""Client administration compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/admin-client-observations.json.
Known differences, listed in IMPLEMENTATION.md: new realms have no built-in
clients, and the representation lists only the modelled settings.
"""

import base64
import hashlib
import json
import pathlib
import secrets
import unittest

from fixture import ENDPOINT, ISSUER_BASE, ServerCase, cli


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/admin-client-observations.json").read_text()
)["observations"]
RUN = secrets.token_hex(4)
ADMIN, ADMIN_SECRET = "client-admin-" + RUN, secrets.token_urlsafe(40)
COMPARED = ["clientId", "enabled", "publicClient", "serviceAccountsEnabled", "standardFlowEnabled", "directAccessGrantsEnabled", "implicitFlowEnabled", "redirectUris", "webOrigins", "protocol", "clientAuthenticatorType", "bearerOnly"]


class AdminClientsContract(ServerCase):
    @classmethod
    def provision(cls):
        assert cli("client", "add-confidential", "master", ADMIN, "https://app.example.test/cb", stdin=ADMIN_SECRET + "\n").returncode == 0
        assert cli("client", "enable-service-account", "master", ADMIN).returncode == 0
        assert cli("client", "grant-master-admin", ADMIN).returncode == 0

    def setUp(self):
        status, _, body = self.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": ADMIN, "client_secret": ADMIN_SECRET})
        self.assertEqual(status, 200)
        self.token = json.loads(body)["access_token"]
        self.realm = "clients-" + secrets.token_hex(6)
        self.assertEqual(self.call("POST", "/admin/realms", {"realm": self.realm, "enabled": True})[0], 201)
        self.clients = f"/admin/realms/{self.realm}/clients"

    def tearDown(self):
        self.call("DELETE", "/admin/realms/" + self.realm)

    def call(self, method, path, payload=None, raw=None, token=True):
        headers = {"Authorization": "Bearer " + self.token} if token else {}
        body = raw if raw is not None else (json.dumps(payload) if payload is not None else None)
        if body is not None:
            headers["Content-Type"] = "application/json"
        return self.request(method, path, headers, body=body)

    def assert_case(self, response, label):
        status, headers, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        pattern = expected.get("location_pattern")
        if pattern:
            prefix = pattern.replace("{base}", ISSUER_BASE).replace("{realm}", self.realm).removesuffix("{id}")
            self.assertTrue(headers.get("location", "").startswith(prefix), label)
        self.assertEqual(not body, expected["empty_body"], label)
        parsed = json.loads(body) if body else None
        for key, value in expected.get("body", {}).items():
            if key in COMPARED or key in ("error", "error_description", "errorMessage", "type", "enabled"):
                self.assertEqual(parsed.get(key), value, f"{label}: {key}")
        if "has_secret" in expected:
            self.assertEqual(bool(parsed.get("secret") or parsed.get("value")), expected["has_secret"], label)
        return response

    def create(self, label, payload):
        response = self.assert_case(self.call("POST", self.clients, payload), label)
        return response[1]["location"].rsplit("/", 1)[1]

    def create_reference_clients(self):
        self.secret = secrets.token_urlsafe(40)
        public = self.create("create/public", {"clientId": "public-app", "publicClient": True, "redirectUris": ["https://app.example.invalid/callback"], "webOrigins": ["https://app.example.invalid"]})
        confidential = self.create("create/confidential", {"clientId": "service-app", "publicClient": False, "secret": self.secret, "serviceAccountsEnabled": True, "standardFlowEnabled": False})
        defaults = self.create("create/defaults", {"clientId": "default-app"})
        return public, confidential, defaults

    def test_create_and_read_clients(self):
        public, confidential, defaults = self.create_reference_clients()
        self.assert_case(self.call("GET", f"{self.clients}/{public}"), "get/public")
        status, _, body = self.assert_case(self.call("GET", f"{self.clients}/{confidential}"), "get/confidential")
        self.assertEqual(json.loads(body)["secret"], self.secret)
        self.assert_case(self.call("GET", f"{self.clients}/{defaults}"), "get/defaults")

    def test_create_errors(self):
        self.create_reference_clients()
        self.assert_case(self.call("POST", self.clients, {"clientId": "public-app"}), "create/duplicate")
        self.assert_case(self.call("POST", self.clients, {"publicClient": True}), "create/missing-client-id")
        self.assert_case(self.call("POST", self.clients, raw="{"), "create/malformed-json")
        self.assert_case(self.call("POST", "/admin/realms/unknown-" + RUN + "/clients", {"clientId": "x"}), "create/unknown-realm")
        self.assert_case(self.call("POST", self.clients, {"clientId": "x"}, token=False), "create/no-token")
        for setting in ({"directAccessGrantsEnabled": True}, {"implicitFlowEnabled": True}, {"bearerOnly": True}, {"protocol": "saml"}, {"redirectUris": ["http://app.example/cb"]}, {"webOrigins": ["*"]}):
            status, _, _ = self.call("POST", self.clients, dict({"clientId": "bad-" + secrets.token_hex(3)}, **setting))
            self.assertEqual(status, 400, setting)

    def test_search(self):
        self.create_reference_clients()
        status, _, body = self.assert_case(self.call("GET", self.clients + "?clientId=public-app"), "search/client-id")
        self.assertEqual([item["clientId"] for item in json.loads(body)], REFERENCE["search/client-id"]["client_ids"])
        status, _, body = self.assert_case(self.call("GET", self.clients + "?clientId=missing-app"), "search/client-id-unknown")
        self.assertEqual(json.loads(body), [])
        listed = {item["clientId"] for item in json.loads(self.call("GET", self.clients)[2])}
        self.assertEqual(listed, {"public-app", "service-app", "default-app"})

    def test_secret_read_and_regenerate_change_authentication(self):
        public, confidential, _ = self.create_reference_clients()
        status, _, body = self.assert_case(self.call("GET", f"{self.clients}/{confidential}/client-secret"), "secret/get")
        self.assertEqual(json.loads(body)["value"], self.secret)
        self.assert_case(self.call("GET", f"{self.clients}/{public}/client-secret"), "secret/get-public")
        token_path = f"/realms/{self.realm}/protocol/openid-connect/token"
        grant = lambda secret: self.request("POST", token_path, form={"grant_type": "client_credentials", "client_id": "service-app", "client_secret": secret})[0]
        self.assertEqual(grant(self.secret), 200)
        status, _, body = self.assert_case(self.call("POST", f"{self.clients}/{confidential}/client-secret"), "secret/regenerate")
        new_secret = json.loads(body)["value"]
        self.assertEqual(grant(self.secret), 401)
        self.assertEqual(grant(new_secret), 200)

    def test_service_account_user(self):
        public, confidential, _ = self.create_reference_clients()
        status, _, body = self.assert_case(self.call("GET", f"{self.clients}/{confidential}/service-account-user"), "service-account/user")
        self.assertEqual(json.loads(body)["username"], "service-account-service-app")
        self.assert_case(self.call("GET", f"{self.clients}/{public}/service-account-user"), "service-account/public")

    def test_disabled_standard_flow_blocks_authorization(self):
        callback = "https://app.example.invalid/callback"
        for name, enabled in (("browser-on", True), ("browser-off", False)):
            self.create("create/public", {"clientId": name, "publicClient": True, "standardFlowEnabled": enabled, "redirectUris": [callback]})
        challenge = base64.urlsafe_b64encode(hashlib.sha256(b"verifier").digest()).rstrip(b"=").decode()
        query = f"response_type=code&scope=openid&code_challenge_method=S256&code_challenge={challenge}&redirect_uri={callback}&client_id="
        auth = f"/realms/{self.realm}/protocol/openid-connect/auth?{query}"
        self.assertEqual(self.request("GET", auth + "browser-on")[0], 200)
        self.assertNotEqual(self.request("GET", auth + "browser-off")[0], 200)

    def test_unknown_and_delete(self):
        public, _, _ = self.create_reference_clients()
        self.assert_case(self.call("GET", f"{self.clients}/00000000-0000-0000-0000-000000000000"), "get/unknown")
        self.assert_case(self.call("DELETE", f"{self.clients}/{public}"), "delete/success")
        self.assert_case(self.call("DELETE", f"{self.clients}/{public}"), "delete/repeat")


if __name__ == "__main__":
    unittest.main()
