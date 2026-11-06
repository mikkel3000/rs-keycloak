"""A partial export imports into another realm as is.

The reference supports this round trip; the export's read-only fields,
masked secrets and service-account users are left out by the import, and
SKIP passes over the built-in clients and roles the new realm already has.
The round trip runs once for the class; each test checks one part of it.
"""

import json
import secrets
import unittest

from fixture import ENDPOINT, AdminCase


class ExportImportContract(AdminCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, _, body = cls.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": cls.ADMIN, "client_secret": cls.ADMIN_SECRET})
        assert status == 200
        headers = {"Authorization": "Bearer " + json.loads(body)["access_token"], "Content-Type": "application/json"}
        call = lambda method, path, payload=None: cls.request(method, path, headers, body=json.dumps(payload) if payload is not None else None)
        cls.headers = headers
        cls.source, cls.target = "export-" + secrets.token_hex(6), "import-" + secrets.token_hex(6)
        for realm in (cls.source, cls.target):
            assert call("POST", "/admin/realms", {"realm": realm, "enabled": True})[0] == 201
        source = f"/admin/realms/{cls.source}"
        assert call("POST", source + "/roles", {"name": "export-role", "description": "Exported"})[0] == 201
        app = call("POST", source + "/clients", {"clientId": "export-app", "secret": secrets.token_urlsafe(40), "serviceAccountsEnabled": True, "redirectUris": ["https://app.example.invalid/cb"]})[1]["location"].rsplit("/", 1)[1]
        assert call("POST", f"{source}/clients/{app}/roles", {"name": "app-role"})[0] == 201
        group = call("POST", source + "/groups", {"name": "export-group"})[1]["location"].rsplit("/", 1)[1]
        assert call("POST", f"{source}/groups/{group}/children", {"name": "export-child"})[0] == 201
        role = json.loads(call("GET", source + "/roles/export-role")[2])
        assert call("POST", f"{source}/groups/{group}/role-mappings/realm", [{"id": role["id"], "name": "export-role"}])[0] == 204
        status, _, body = call("POST", source + "/partial-export?exportGroupsAndRoles=true&exportClients=true")
        assert status == 200
        cls.import_status, _, cls.import_body = call("POST", f"/admin/realms/{cls.target}/partialImport", dict(json.loads(body), ifResourceExists="SKIP"))

    @classmethod
    def tearDownClass(cls):
        for realm in (cls.source, cls.target):
            cls.request("DELETE", "/admin/realms/" + realm, cls.headers)
        super().tearDownClass()

    def setUp(self):
        self.base = f"/admin/realms/{self.target}"

    def tearDown(self):
        pass

    def get(self, path):
        return json.loads(self.request("GET", self.base + path, self.headers)[2])

    def test_import_adds_the_custom_resources(self):
        self.assertEqual(self.import_status, 200, self.import_body)
        added = {(item["resourceType"], item["resourceName"]) for item in json.loads(self.import_body)["results"] if item["action"] == "ADDED"}
        self.assertLessEqual({("CLIENT", "export-app"), ("REALM_ROLE", "export-role"), ("CLIENT_ROLE", "export-app-->app-role"), ("GROUP", "export-group")}, added)

    def test_client_arrives_with_a_new_secret_and_its_role(self):
        client = self.get("/clients?clientId=export-app")[0]
        self.assertEqual((client["publicClient"], client["serviceAccountsEnabled"], client["redirectUris"]), (False, True, ["https://app.example.invalid/cb"]))
        self.assertNotEqual(self.get(f"/clients/{client['id']}/client-secret")["value"], "**********")
        self.assertEqual([item["name"] for item in self.get(f"/clients/{client['id']}/roles")], ["app-role"])
        self.assertEqual(self.request("GET", f"{self.base}/clients/{client['id']}/service-account-user", self.headers)[0], 200)

    def test_roles_and_groups_arrive(self):
        self.assertEqual(self.get("/roles/export-role")["description"], "Exported")
        imported = next(item for item in self.get("/groups") if item["name"] == "export-group")
        self.assertEqual(self.get(f"/groups/{imported['id']}")["realmRoles"], ["export-role"])
        self.assertEqual([item["name"] for item in self.get(f"/groups/{imported['id']}/children")], ["export-child"])


if __name__ == "__main__":
    unittest.main()
