"""Realm roles and user role mappings compared with recorded Keycloak 26.8.1.

Expected cases come from tests/reference/admin-role-observations.json.
"""

import json
import pathlib
import secrets
import unittest

from fixture import ENDPOINT, ISSUER_BASE, ServerCase, cli


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/admin-role-observations.json").read_text()
)["observations"]
RUN = secrets.token_hex(4)
ADMIN, ADMIN_SECRET = "role-admin-" + RUN, secrets.token_urlsafe(40)


class AdminRolesContract(ServerCase):
    @classmethod
    def provision(cls):
        assert cli("client", "add-confidential", "master", ADMIN, "https://app.example.test/cb", stdin=ADMIN_SECRET + "\n").returncode == 0
        assert cli("client", "enable-service-account", "master", ADMIN).returncode == 0
        assert cli("client", "grant-master-admin", ADMIN).returncode == 0

    def setUp(self):
        status, _, body = self.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": ADMIN, "client_secret": ADMIN_SECRET})
        self.assertEqual(status, 200)
        self.token = json.loads(body)["access_token"]
        self.realm = "roles-" + secrets.token_hex(6)
        self.assertEqual(self.call("POST", "/admin/realms", {"realm": self.realm, "enabled": True})[0], 201)
        self.roles = f"/admin/realms/{self.realm}/roles"

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
        location = expected.get("location")
        self.assertEqual(headers.get("location"), location.replace("{base}", ISSUER_BASE).replace("{realm}", self.realm) if location else None, label)
        self.assertEqual(not body, expected["empty_body"], label)
        parsed = json.loads(body) if body else None
        for key, value in expected.get("body", {}).items():
            self.assertEqual(parsed.get(key), value, f"{label}: {key}")
        if "names" in expected:
            names = sorted(item.get("name") or item.get("username") for item in parsed)
            self.assertEqual(names, [name.replace("{realm}", self.realm) for name in expected["names"]], label)
            if parsed and "name" in parsed[0]:
                self.assertEqual(sorted({field for item in parsed for field in item}), expected["item_fields"], label)
        if "body_fields" in expected and isinstance(parsed, dict) and label.startswith("get/success"):
            self.assertEqual(sorted(parsed), expected["body_fields"], label)
        return parsed

    def test_role_lifecycle(self):
        self.assert_case(self.call("GET", self.roles), "list/defaults")
        self.assert_case(self.call("POST", self.roles, {"name": "reader", "description": "Reads things"}), "create/success")
        self.assert_case(self.call("POST", self.roles, {"name": "writer"}), "create/second")
        self.assert_case(self.call("POST", self.roles, {"name": "reader"}), "create/duplicate")
        self.assert_case(self.call("POST", self.roles, {"description": "x"}), "create/missing-name")
        self.assert_case(self.call("POST", self.roles, raw="{"), "create/malformed-json")
        self.assert_case(self.call("POST", self.roles, {"name": "x"}, token=False), "create/no-token")
        self.assert_case(self.call("GET", self.roles + "/reader"), "get/success")
        self.assert_case(self.call("GET", self.roles + "/missing-role"), "get/unknown")
        self.assert_case(self.call("GET", self.roles), "list/after-create")
        self.assert_case(self.call("DELETE", self.roles + "/writer"), "delete/success")
        self.assert_case(self.call("DELETE", self.roles + "/writer"), "delete/repeat")
        status, _, _ = self.call("DELETE", f"{self.roles}/default-roles-{self.realm}")
        self.assertEqual(status, 400)

    def test_user_role_mappings(self):
        self.call("POST", self.roles, {"name": "reader"})
        created = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "role-user", "enabled": True})
        mappings = created[1]["location"].replace(ISSUER_BASE, "") + "/role-mappings/realm"
        reader = json.loads(self.call("GET", self.roles + "/reader")[2])
        self.assert_case(self.call("GET", mappings), "mappings/initial")
        self.assert_case(self.call("POST", mappings, [{"id": reader["id"], "name": "reader"}]), "mappings/add")
        self.assert_case(self.call("POST", mappings, [{"id": reader["id"], "name": "reader"}]), "mappings/add-repeat")
        self.assert_case(self.call("POST", mappings, [{"id": "00000000-0000-0000-0000-000000000000", "name": "missing-role"}]), "mappings/add-unknown")
        self.assert_case(self.call("GET", mappings), "mappings/after-add")
        self.assert_case(self.call("GET", self.roles + "/reader/users"), "role-users")
        self.assert_case(self.call("DELETE", mappings, [{"id": reader["id"], "name": "reader"}]), "mappings/remove")
        self.assert_case(self.call("GET", mappings), "mappings/after-remove")

    def test_service_accounts_hold_the_default_role(self):
        created = self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "svc", "serviceAccountsEnabled": True, "standardFlowEnabled": False})
        client = created[1]["location"].replace(ISSUER_BASE, "")
        user = json.loads(self.call("GET", client + "/service-account-user")[2])
        mapped = json.loads(self.call("GET", f"/admin/realms/{self.realm}/users/{user['id']}/role-mappings/realm")[2])
        self.assertEqual([role["name"] for role in mapped], [f"default-roles-{self.realm}"])

    def test_granted_and_composite_roles_reach_tokens(self):
        secret = secrets.token_urlsafe(40)
        created = self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "svc", "secret": secret, "serviceAccountsEnabled": True, "standardFlowEnabled": False})
        client = created[1]["location"].replace(ISSUER_BASE, "")
        user = json.loads(self.call("GET", client + "/service-account-user")[2])
        self.call("POST", self.roles, {"name": "reader"})
        reader = json.loads(self.call("GET", self.roles + "/reader")[2])
        self.call("POST", f"/admin/realms/{self.realm}/users/{user['id']}/role-mappings/realm", [{"id": reader["id"], "name": "reader"}])
        status, _, body = self.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token", form={"grant_type": "client_credentials", "client_id": "svc", "client_secret": secret})
        self.assertEqual(status, 200)
        claims = self.verify(json.loads(body)["access_token"])
        self.assertEqual(claims["realm_access"]["roles"], sorted([f"default-roles-{self.realm}", "offline_access", "reader", "uma_authorization"]))


if __name__ == "__main__":
    unittest.main()
