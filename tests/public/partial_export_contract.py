"""Realm partial export compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/partial-export-observations.json.
Known difference, listed in IMPLEMENTATION.md: the realm representation has
fewer fields and no `components`, so sections are compared, not field
counts.
"""

import json
import pathlib
import secrets
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/partial-export-observations.json").read_text()
)["observations"]
SECTIONS = ("clients", "roles", "groups", "users", "clientScopes", "defaultRole", "requiredActions")


class PartialExportContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.base = f"/admin/realms/{self.realm}"
        self.secret = secrets.token_urlsafe(40)
        self.assertEqual(self.call("POST", self.base + "/roles", {"name": "export-role"})[0], 201)
        app = self.call("POST", self.base + "/clients", {"clientId": "export-app", "secret": self.secret, "serviceAccountsEnabled": True})[1]["location"].rsplit("/", 1)[1]
        self.assertEqual(self.call("POST", f"{self.base}/clients/{app}/roles", {"name": "app-role"})[0], 201)
        group = self.call("POST", self.base + "/groups", {"name": "export-group"})[1]["location"].rsplit("/", 1)[1]
        role = json.loads(self.call("GET", self.base + "/roles/export-role")[2])
        self.assertEqual(self.call("POST", f"{self.base}/groups/{group}/role-mappings/realm", [{"id": role["id"], "name": "export-role"}])[0], 204)
        self.assertEqual(self.call("POST", self.base + "/users", {"username": "export-user", "enabled": True})[0], 201)

    def check(self, label, query):
        status, headers, body = self.call("POST", self.base + "/partial-export" + query)
        expected = REFERENCE[label]
        self.assertEqual((status, headers["content-type"].split(";")[0]), (expected["status"], expected["content_type"]), label)
        parsed = json.loads(body)
        self.assertEqual(sorted(key for key in SECTIONS if key in parsed), [key for key in expected["has"] if key in SECTIONS], label)
        clients = {item["clientId"]: item for item in parsed.get("clients", [])}
        self.assertEqual(sorted(clients), expected["client_ids"], label)
        self.assertEqual(clients.get("export-app", {}).get("secret"), expected["secret"], label)
        self.assertNotIn(self.secret, body.decode(), label)
        self.assertEqual(sorted(role["name"].replace(self.realm, "{realm}") for role in parsed.get("roles", {}).get("realm", [])), expected["realm_roles"], label)
        self.assertEqual(sorted(role["name"] for role in parsed.get("roles", {}).get("client", {}).get("export-app", [])), expected["client_roles"], label)
        self.assertEqual(sorted(group["path"] for group in parsed.get("groups", [])), expected["groups"], label)
        self.assertEqual(next((group.get("realmRoles") for group in parsed.get("groups", []) if group["name"] == "export-group"), None), expected["group_roles"], label)
        self.assertNotIn("export-user", [user["username"] for user in parsed.get("users", [])], label)

    def test_default_export(self):
        self.check("export/default", "")

    def test_groups_and_roles(self):
        self.check("export/groups-roles", "?exportGroupsAndRoles=true")

    def test_clients(self):
        self.check("export/clients", "?exportClients=true")

    def test_everything(self):
        self.check("export/everything", "?exportGroupsAndRoles=true&exportClients=true")

    def test_unknown_realm(self):
        status, _, body = self.call("POST", "/admin/realms/missing-realm/partial-export")
        self.assertEqual({"status": status, "body": json.loads(body)}, REFERENCE["export/unknown-realm"])


if __name__ == "__main__":
    unittest.main()
