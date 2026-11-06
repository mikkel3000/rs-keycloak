"""Client roles compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/client-role-observations.json. The
token audience differs: tokens here name their own client as audience.
"""

import json
import pathlib
import secrets
import unittest

from fixture import ISSUER_BASE, AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/client-role-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


class ClientRolesContract(AdminCase):
    def setUp(self):
        super().setUp()
        base = f"/admin/realms/{self.realm}"
        self.assertEqual(self.call("POST", base + "/clients", {"clientId": "roles-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        clients = json.loads(self.call("GET", base + "/clients")[2])
        self.ids = {client["clientId"]: client["id"] for client in clients}
        self.app = self.ids["roles-app"]
        location = self.call("POST", base + "/users", {"username": "reference-user", "enabled": True})[1]["location"]
        self.user = location.rsplit("/", 1)[1]
        self.password = secrets.token_urlsafe(30)
        self.call("PUT", f"{base}/users/{self.user}/reset-password", {"type": "password", "value": self.password})
        self.base = base

    def case(self, response, label, location=None):
        status, headers, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        self.assertEqual(not body, expected["empty_body"], label)
        parsed = json.loads(body) if body else None
        if "body" in expected:
            for key, value in expected["body"].items():
                self.assertEqual(parsed.get(key), value, f"{label}: {key}")
        if "names" in expected:
            self.assertEqual(sorted(item["name"] for item in parsed), [n.replace("{realm}", self.realm) for n in expected["names"]], label)
        if location:
            self.assertEqual(headers.get("location"), location, label)
        return parsed

    def test_builtin_account_roles_and_default_composites(self):
        self.case(self.call("GET", f"{self.base}/clients/{self.ids['account']}/roles"), "account/roles")
        default = f"{self.base}/roles/default-roles-{self.realm}"
        mapped = json.loads(self.call("GET", f"{self.base}/users/{self.user}/role-mappings/realm")[2])
        self.assertEqual([role["name"] for role in mapped], [f"default-roles-{self.realm}"])
        status, _, body = self.call("GET", f"/admin/realms/{self.realm}/clients/{self.ids['account']}/roles/manage-account")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["composite"])
        self.assertEqual(self.call("GET", default)[0], 200)
        composites = self.case(self.call("GET", default + "/composites"), "default-role/composites")
        self.assertEqual(sorted({field for item in composites for field in item}), REFERENCE["default-role/composites"]["item_fields"])

    def test_client_role_lifecycle(self):
        roles = f"{self.base}/clients/{self.app}/roles"
        location = f"{ISSUER_BASE}/admin/realms/{self.realm}/clients/{self.app}/roles/editor"
        self.case(self.call("POST", roles, {"name": "editor", "description": "Edits"}), "create/success", location)
        self.case(self.call("POST", roles, {"name": "editor"}), "create/duplicate")
        self.case(self.call("POST", roles, {}), "create/missing-name")
        self.case(self.call("POST", f"{self.base}/clients/00000000-0000-0000-0000-000000000000/roles", {"name": "x"}), "create/unknown-client")
        self.case(self.call("GET", roles), "list")
        editor = self.case(self.call("GET", roles + "/editor"), "get")
        self.assertEqual((editor["clientRole"], editor["containerId"] == self.app), (REFERENCE["get"]["client_role"], REFERENCE["get"]["container_is_client"]))
        self.assertEqual(sorted(editor), REFERENCE["get"]["body_fields"])
        self.case(self.call("GET", roles + "/missing"), "get/unknown")
        self.case(self.call("DELETE", roles + "/editor"), "delete")
        self.case(self.call("DELETE", roles + "/editor"), "delete/repeat")

    def test_client_role_mappings_reach_tokens(self):
        roles = f"{self.base}/clients/{self.app}/roles"
        self.assertEqual(self.call("POST", roles, {"name": "editor", "description": "Edits"})[0], 201)
        editor = json.loads(self.call("GET", roles + "/editor")[2])
        mappings = f"{self.base}/users/{self.user}/role-mappings/clients/{self.app}"
        self.case(self.call("GET", mappings), "mappings/initial")
        self.case(self.call("POST", mappings, [{"id": editor["id"], "name": "editor"}]), "mappings/add")
        self.case(self.call("POST", mappings, [{"id": "00000000-0000-0000-0000-000000000000", "name": "missing"}]), "mappings/add-unknown")
        self.case(self.call("GET", mappings), "mappings/after-add")
        claims = self.verify(self.browser_login(self.realm, "roles-app", CALLBACK, "reference-user", self.password)["access_token"])
        self.assertEqual({client: sorted(entry["roles"]) for client, entry in sorted(claims["resource_access"].items())}, REFERENCE["token/resource_access"])
        self.case(self.call("DELETE", mappings, [{"id": editor["id"], "name": "editor"}]), "mappings/remove")
        self.case(self.call("GET", mappings), "mappings/after-remove")


if __name__ == "__main__":
    unittest.main()
