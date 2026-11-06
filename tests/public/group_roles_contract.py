"""Group role mappings compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/group-role-observations.json.
"""

import json
import pathlib
import secrets
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/group-role-observations.json").read_text()
)["observations"]


class GroupRolesContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.base = f"/admin/realms/{self.realm}"
        self.secret = secrets.token_urlsafe(40)
        for name in ("parent-role", "child-role"):
            self.assertEqual(self.call("POST", self.base + "/roles", {"name": name})[0], 201)
        status, headers, _ = self.call("POST", self.base + "/clients", {"clientId": "member-app", "secret": self.secret, "serviceAccountsEnabled": True, "standardFlowEnabled": False})
        self.assertEqual(status, 201)
        self.app = headers["location"].rsplit("/", 1)[1]
        self.assertEqual(self.call("POST", f"{self.base}/clients/{self.app}/roles", {"name": "app-role"})[0], 201)
        self.parent = self.call("POST", self.base + "/groups", {"name": "parent"})[1]["location"].rsplit("/", 1)[1]
        self.child = json.loads(self.call("POST", f"{self.base}/groups/{self.parent}/children", {"name": "child"})[2])["id"]
        self.member = json.loads(self.call("GET", f"{self.base}/clients/{self.app}/service-account-user")[2])["id"]
        self.roles = {name: json.loads(self.call("GET", f"{self.base}/roles/{name}")[2]) for name in ("parent-role", "child-role")}
        self.roles["app-role"] = json.loads(self.call("GET", f"{self.base}/clients/{self.app}/roles/app-role")[2])

    def mapping(self, name):
        return [{"id": self.roles[name]["id"], "name": name}]

    def case(self, response, label):
        status, _, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        self.assertEqual(not body, expected["empty_body"], label)
        parsed = json.loads(body) if body else None
        for key, value in expected.get("body", {}).items():
            self.assertEqual(parsed.get(key), value, f"{label}: {key}")
        if "names" in expected:
            self.assertEqual(sorted(item["name"].replace(self.realm, "{realm}") for item in parsed), expected["names"], label)
        return parsed

    def claims(self, label):
        status, _, body = self.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token", form={"grant_type": "client_credentials", "client_id": "member-app", "client_secret": self.secret})
        self.assertEqual(status, 200)
        claims = self.verify(json.loads(body)["access_token"])
        observed = {
            "realm_access": sorted(name.replace(self.realm, "{realm}") for name in claims.get("realm_access", {}).get("roles", [])),
            "resource_access": {client: sorted(entry["roles"]) for client, entry in sorted(claims.get("resource_access", {}).items())},
        }
        self.assertEqual(observed, REFERENCE[label], label)

    def test_mappings_and_errors(self):
        realm_mappings = f"{self.base}/groups/{self.parent}/role-mappings/realm"
        self.case(self.call("GET", realm_mappings), "realm/initial")
        self.case(self.call("POST", realm_mappings, self.mapping("parent-role")), "realm/add")
        self.case(self.call("POST", f"{self.base}/groups/{self.child}/role-mappings/realm", self.mapping("child-role")), "realm/add-child")
        self.case(self.call("POST", realm_mappings, [{"id": "00000000-0000-0000-0000-000000000000", "name": "missing"}]), "realm/add-unknown-role")
        self.case(self.call("GET", f"{self.base}/groups/00000000-0000-0000-0000-000000000000/role-mappings/realm"), "realm/unknown-group")
        self.case(self.call("GET", realm_mappings), "realm/after-add")
        client_mappings = f"{self.base}/groups/{self.child}/role-mappings/clients/{self.app}"
        self.case(self.call("POST", client_mappings, self.mapping("app-role")), "client/add")
        self.case(self.call("GET", client_mappings), "client/after-add")
        group = self.case(self.call("GET", f"{self.base}/groups/{self.parent}"), "group/full")
        self.assertEqual(group["realmRoles"], REFERENCE["group/full"]["realm_roles"])
        self.case(self.call("DELETE", realm_mappings, self.mapping("parent-role")), "realm/remove")
        self.case(self.call("GET", realm_mappings), "realm/after-remove")

    def test_members_inherit_group_roles(self):
        self.assertEqual(self.call("POST", f"{self.base}/groups/{self.parent}/role-mappings/realm", self.mapping("parent-role"))[0], 204)
        self.assertEqual(self.call("POST", f"{self.base}/groups/{self.child}/role-mappings/realm", self.mapping("child-role"))[0], 204)
        self.assertEqual(self.call("POST", f"{self.base}/groups/{self.child}/role-mappings/clients/{self.app}", self.mapping("app-role"))[0], 204)
        self.claims("token/before-join")
        self.assertEqual(self.call("PUT", f"{self.base}/users/{self.member}/groups/{self.child}")[0], 204)
        self.claims("token/member-of-child")
        self.case(self.call("GET", f"{self.base}/users/{self.member}/role-mappings/realm"), "user/direct-realm")
        self.case(self.call("GET", f"{self.base}/users/{self.member}/role-mappings/realm/composite"), "user/effective-realm")
        self.case(self.call("GET", f"{self.base}/roles/parent-role/users"), "role/users")

    def test_unmapping_and_group_deletion_remove_roles(self):
        self.assertEqual(self.call("POST", f"{self.base}/groups/{self.parent}/role-mappings/realm", self.mapping("parent-role"))[0], 204)
        self.assertEqual(self.call("POST", f"{self.base}/groups/{self.child}/role-mappings/realm", self.mapping("child-role"))[0], 204)
        self.assertEqual(self.call("POST", f"{self.base}/groups/{self.child}/role-mappings/clients/{self.app}", self.mapping("app-role"))[0], 204)
        self.assertEqual(self.call("PUT", f"{self.base}/users/{self.member}/groups/{self.child}")[0], 204)
        self.assertEqual(self.call("DELETE", f"{self.base}/groups/{self.parent}/role-mappings/realm", self.mapping("parent-role"))[0], 204)
        self.claims("token/after-remove")
        self.case(self.call("DELETE", f"{self.base}/groups/{self.child}"), "group/delete-child")
        self.claims("token/after-delete")
        self.case(self.call("DELETE", f"{self.base}/roles/child-role"), "role/delete-mapped")


if __name__ == "__main__":
    unittest.main()
