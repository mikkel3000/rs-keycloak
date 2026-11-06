"""Combined role mappings compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/role-mapping-observations.json.
"""

import json
import pathlib
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/role-mapping-observations.json").read_text()
)["observations"]


class RoleMappingsContract(AdminCase):
    def shape(self, response):
        status, _, body = response
        parsed = json.loads(body)
        if status != 200:
            return {"status": status, "error": parsed.get("error")}
        return {
            "status": status,
            "fields": sorted(parsed),
            "realm": sorted(role["name"].replace(self.realm, "{realm}") for role in parsed.get("realmMappings", [])),
            "clients": {
                name: {"fields": sorted(entry), "client": entry.get("client"), "id_is_uuid": len(entry.get("id", "")) == 36, "mappings": sorted(role["name"] for role in entry["mappings"])}
                for name, entry in sorted(parsed.get("clientMappings", {}).items())
            },
            "role_fields": sorted({field for role in parsed.get("realmMappings", []) for field in role}),
        }

    def test_users_and_groups(self):
        base = f"/admin/realms/{self.realm}"
        self.assertEqual(self.call("POST", base + "/roles", {"name": "mapped"})[0], 201)
        app = self.call("POST", base + "/clients", {"clientId": "mapped-app", "publicClient": True})[1]["location"].rsplit("/", 1)[1]
        self.assertEqual(self.call("POST", f"{base}/clients/{app}/roles", {"name": "app-role"})[0], 201)
        user = self.call("POST", base + "/users", {"username": "mapped-user", "enabled": True})[1]["location"].rsplit("/", 1)[1]
        group = self.call("POST", base + "/groups", {"name": "mapped-group"})[1]["location"].rsplit("/", 1)[1]
        mapped = json.loads(self.call("GET", base + "/roles/mapped")[2])
        app_role = json.loads(self.call("GET", f"{base}/clients/{app}/roles/app-role")[2])
        self.assertEqual(self.shape(self.call("GET", f"{base}/users/{user}/role-mappings")), REFERENCE["user/initial"])
        self.assertEqual(self.shape(self.call("GET", f"{base}/groups/{group}/role-mappings")), REFERENCE["group/initial"])
        for holder in (f"{base}/users/{user}", f"{base}/groups/{group}"):
            self.assertEqual(self.call("POST", holder + "/role-mappings/realm", [{"id": mapped["id"], "name": "mapped"}])[0], 204)
            self.assertEqual(self.call("POST", f"{holder}/role-mappings/clients/{app}", [{"id": app_role["id"], "name": "app-role"}])[0], 204)
        self.assertEqual(self.shape(self.call("GET", f"{base}/users/{user}/role-mappings")), REFERENCE["user/mapped"])
        self.assertEqual(self.shape(self.call("GET", f"{base}/groups/{group}/role-mappings")), REFERENCE["group/mapped"])
        self.assertEqual(self.shape(self.call("GET", base + "/users/00000000-0000-0000-0000-000000000000/role-mappings")), REFERENCE["user/unknown"])
        self.assertEqual(self.shape(self.call("GET", base + "/groups/00000000-0000-0000-0000-000000000000/role-mappings")), REFERENCE["group/unknown"])


if __name__ == "__main__":
    unittest.main()
