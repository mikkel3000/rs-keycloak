"""Partial import of groups and role mappings compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/partial-import-group-observations.json.
Imported users also hold the realm's default role here, so their realm
roles are compared without it.
"""

import json
import pathlib
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/partial-import-group-observations.json").read_text()
)["observations"]
PAYLOAD = {
    "ifResourceExists": "FAIL",
    "roles": {"realm": [{"name": "imported-role"}], "client": {"imported-app": [{"name": "imported-app-role"}]}},
    "clients": [{"clientId": "imported-app", "publicClient": True}],
    "groups": [{"name": "imported-group", "path": "/imported-group", "realmRoles": ["imported-role"], "clientRoles": {"imported-app": ["imported-app-role"]}, "subGroups": [{"name": "imported-child", "path": "/imported-group/imported-child"}]}],
    "users": [{"username": "imported-user", "enabled": True, "realmRoles": ["imported-role"], "clientRoles": {"imported-app": ["imported-app-role"]}, "groups": ["/imported-group/imported-child"]}],
}


class PartialImportGroupsContract(AdminCase):
    def get(self, path):
        return json.loads(self.call("GET", f"/admin/realms/{self.realm}" + path)[2])

    def import_(self, policy):
        status, _, body = self.call("POST", f"/admin/realms/{self.realm}/partialImport", dict(PAYLOAD, ifResourceExists=policy))
        return status, json.loads(body)

    def test_import_and_skip(self):
        status, parsed = self.import_("FAIL")
        self.assertEqual({"status": status, "added": parsed.get("added"), "results": sorted([item["action"], item["resourceType"], item["resourceName"]] for item in parsed["results"]), "error": None}, REFERENCE["import"])
        group = next(item for item in self.get("/groups") if item["name"] == "imported-group")
        full = self.get(f"/groups/{group['id']}")
        self.assertEqual({"realm_roles": full["realmRoles"], "client_roles": full["clientRoles"], "children": sorted(item["name"] for item in self.get(f"/groups/{group['id']}/children"))}, REFERENCE["group"])
        client = self.get("/clients?clientId=imported-app")[0]
        self.assertEqual(sorted(role["name"] for role in self.get(f"/clients/{client['id']}/roles")), REFERENCE["client-roles"])
        user = self.get("/users?username=imported-user&exact=true")[0]
        realm_roles = sorted(role["name"] for role in self.get(f"/users/{user['id']}/role-mappings/realm") if not role["name"].startswith("default-roles-"))
        self.assertEqual({"realm_roles": realm_roles, "client_roles": sorted(role["name"] for role in self.get(f"/users/{user['id']}/role-mappings/clients/{client['id']}")), "groups": sorted(item["path"] for item in self.get(f"/users/{user['id']}/groups"))}, REFERENCE["user"])
        status, parsed = self.import_("SKIP")
        self.assertEqual({"status": status, "skipped": parsed["skipped"], "results": sorted([item["action"], item["resourceType"], item["resourceName"]] for item in parsed["results"])}, REFERENCE["import/skip"])


if __name__ == "__main__":
    unittest.main()
