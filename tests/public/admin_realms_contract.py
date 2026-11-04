"""Realm administration compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/admin-realm-observations.json. The
realm representation holds only id, realm and enabled until the remaining
fields are modelled; see IMPLEMENTATION.md.
"""

import json
import pathlib
import secrets
import unittest

from fixture import ENDPOINT, ISSUER_BASE, ServerCase, cli


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/admin-realm-observations.json").read_text()
)["observations"]
RUN = secrets.token_hex(4)
ADMIN, ADMIN_SECRET = "admin-client-" + RUN, secrets.token_urlsafe(40)
PLAIN, PLAIN_SECRET = "plain-client-" + RUN, secrets.token_urlsafe(40)


def realm_name():
    return "contract-" + secrets.token_hex(6)


class AdminRealmsContract(ServerCase):
    @classmethod
    def provision(cls):
        for client, secret in ((ADMIN, ADMIN_SECRET), (PLAIN, PLAIN_SECRET)):
            assert cli("client", "add-confidential", "master", client, "https://app.example.test/cb", stdin=secret + "\n").returncode == 0
            assert cli("client", "enable-service-account", "master", client).returncode == 0
        for _ in range(2):
            assert cli("client", "grant-master-admin", ADMIN).returncode == 0
        assert cli("client", "grant-master-admin", "missing-" + RUN).returncode != 0

    def token(self, client=ADMIN, secret=ADMIN_SECRET):
        status, _, body = self.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": client, "client_secret": secret})
        self.assertEqual(status, 200)
        return json.loads(body)["access_token"]

    def call(self, method, path, token=None, payload=None, raw=None):
        headers = {"Authorization": "Bearer " + token} if token else {}
        body = raw if raw is not None else (json.dumps(payload) if payload is not None else None)
        if body is not None:
            headers["Content-Type"] = "application/json"
        return self.request(method, path, headers, body=body)

    def assert_case(self, response, label, realm=None):
        status, headers, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        location = expected.get("location")
        if location:
            location = location.replace("{base}", ISSUER_BASE).replace("{realm}", realm)
        self.assertEqual(headers.get("location"), location, label)
        self.assertEqual(not body, expected["empty_body"], label)
        if body and "body" in expected:
            parsed = json.loads(body)
            for key, value in expected["body"].items():
                self.assertEqual(parsed.get(key), value.replace("{realm}", realm) if isinstance(value, str) and realm else value, label)
            self.assertEqual("id" in parsed, expected["has_id"], label)

    def test_create_requires_a_token(self):
        self.assert_case(self.call("POST", "/admin/realms", payload={"realm": realm_name(), "enabled": True}), "create/no-token")

    def test_create_rejects_invalid_token(self):
        self.assert_case(self.call("POST", "/admin/realms", "not-a-token", {"realm": realm_name(), "enabled": True}), "create/invalid-token")

    def test_create_requires_admin_role(self):
        self.assert_case(self.call("POST", "/admin/realms", self.token(PLAIN, PLAIN_SECRET), {"realm": realm_name(), "enabled": True}), "create/unprivileged")

    def test_create_read_and_delete_realm(self):
        token, realm = self.token(), realm_name()
        self.assert_case(self.call("POST", "/admin/realms", token, {"realm": realm, "enabled": True}), "create/success", realm)
        self.assert_case(self.call("POST", "/admin/realms", token, {"realm": realm, "enabled": True}), "create/duplicate", realm)
        read = self.call("GET", "/admin/realms/" + realm, token)
        self.assert_case(read, "get/success", realm)
        self.assertEqual(read[1].get("content-type"), REFERENCE["get/success"]["content_type"])
        self.assertEqual(self.call("GET", f"/realms/{realm}/.well-known/openid-configuration")[0], REFERENCE["discovery/new-realm"]["status"])
        self.assert_case(self.call("DELETE", "/admin/realms/" + realm, token), "delete/success", realm)
        self.assert_case(self.call("DELETE", "/admin/realms/" + realm, token), "delete/repeat", realm)
        self.assert_case(self.call("GET", f"/realms/{realm}/.well-known/openid-configuration"), "discovery/deleted-realm", realm)

    def test_disabled_realm_still_serves_discovery(self):
        token, realm = self.token(), realm_name()
        self.assert_case(self.call("POST", "/admin/realms", token, {"realm": realm, "enabled": False}), "create/disabled", realm)
        self.assert_case(self.call("GET", f"/realms/{realm}/.well-known/openid-configuration"), "discovery/disabled-realm", realm)
        self.assert_case(self.call("GET", "/admin/realms/" + realm, token), "get/disabled", realm)
        self.assert_case(self.call("DELETE", "/admin/realms/" + realm, token), "delete/disabled", realm)

    def test_create_validation_errors(self):
        token = self.token()
        self.assert_case(self.call("POST", "/admin/realms", token, {"enabled": True}), "create/missing-name")
        self.assert_case(self.call("POST", "/admin/realms", token, raw="{"), "create/malformed-json")

    def test_unsupported_fields_are_refused(self):
        status, _, body = self.call("POST", "/admin/realms", self.token(), {"realm": realm_name(), "sslRequired": "none"})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"errorMessage": "Unsupported realm field: sslRequired"})

    def test_read_errors(self):
        token = self.token()
        self.assert_case(self.call("GET", "/admin/realms/unknown-" + RUN, token), "get/unknown")
        self.assert_case(self.call("GET", "/admin/realms/master", self.token(PLAIN, PLAIN_SECRET)), "get/unprivileged")
        self.assert_case(self.call("GET", "/admin/realms/master"), "get/no-token")

    def test_master_realm_cannot_be_deleted(self):
        status, _, body = self.call("DELETE", "/admin/realms/master", self.token())
        self.assertEqual((status, json.loads(body)), (400, {"errorMessage": "Can't remove master realm"}))

    def test_realm_with_clients_can_be_deleted(self):
        token, realm = self.token(), realm_name()
        self.assertEqual(self.call("POST", "/admin/realms", token, {"realm": realm, "enabled": True})[0], 201)
        self.assertEqual(cli("client", "add-public", realm, "app", "https://app.example.test/cb").returncode, 0)
        self.assertEqual(cli("client", "add-web-origin", realm, "app", "https://app.example.test").returncode, 0)
        self.assertEqual(self.call("DELETE", "/admin/realms/" + realm, token)[0], 204)
        self.assertEqual(self.call("GET", "/admin/realms/" + realm, token)[0], 404)


if __name__ == "__main__":
    unittest.main()
