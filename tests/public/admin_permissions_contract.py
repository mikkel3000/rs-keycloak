"""Realm-scoped admin access compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/admin-permission-observations.json:
service-account tokens of the managed realm, each holding no role or one
realm-management role. A full realm representation has fewer fields here,
so field names are compared only for the brief one, without `displayName`,
which the reference shows once an earlier case had set it and this server
does not store.
"""

import json
import pathlib
import secrets
import unittest

from fixture import ENDPOINT, AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/admin-permission-observations.json").read_text()
)["observations"]
ROLES = sorted({label.split("/", 1)[0] for label in REFERENCE})


class AdminPermissionsContract(AdminCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, _, body = cls.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": cls.ADMIN, "client_secret": cls.ADMIN_SECRET})
        assert status == 200
        cls.master_token = json.loads(body)["access_token"]
        cls.other = "other-" + secrets.token_hex(6)
        headers = {"Authorization": "Bearer " + cls.master_token, "Content-Type": "application/json"}
        assert cls.request("POST", "/admin/realms", headers, body=json.dumps({"realm": cls.other, "enabled": True}))[0] == 201

    @classmethod
    def tearDownClass(cls):
        cls.request("DELETE", "/admin/realms/" + cls.other, {"Authorization": "Bearer " + cls.master_token})
        super().tearDownClass()

    def realm_token(self, role):
        base = f"/admin/realms/{self.realm}"
        secret = secrets.token_urlsafe(40)
        status, headers, _ = self.call("POST", base + "/clients", {"clientId": "sa-" + role, "secret": secret, "serviceAccountsEnabled": True, "standardFlowEnabled": False})
        self.assertEqual(status, 201)
        client = headers["location"].rsplit("/", 1)[1]
        user = json.loads(self.call("GET", f"{base}/clients/{client}/service-account-user")[2])["id"]
        if role != "none":
            management = json.loads(self.call("GET", base + "/clients?clientId=realm-management")[2])[0]["id"]
            described = json.loads(self.call("GET", f"{base}/clients/{management}/roles/{role}")[2])
            self.assertEqual(self.call("POST", f"{base}/users/{user}/role-mappings/clients/{management}", [{"id": described["id"], "name": role}])[0], 204)
        status, _, body = self.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token", form={"grant_type": "client_credentials", "client_id": "sa-" + role, "client_secret": secret})
        self.assertEqual(status, 200)
        return json.loads(body)["access_token"]

    def check_role(self, role):
        token = self.realm_token(role)
        base = f"/admin/realms/{self.realm}"
        target_user = self.call("POST", base + "/users", {"username": "target-user", "enabled": True})[1]["location"].rsplit("/", 1)[1]
        target_client = self.call("POST", base + "/clients", {"clientId": "target-client", "publicClient": True})[1]["location"].rsplit("/", 1)[1]
        self.assertEqual(self.call("POST", base + "/groups", {"name": "target-group"})[0], 201)
        operations = [
            ("realm/get", "GET", base, None),
            ("realm/update", "PUT", base, {"enabled": True}),
            ("users/list", "GET", base + "/users", None),
            ("users/count", "GET", base + "/users/count", None),
            ("users/get", "GET", f"{base}/users/{target_user}", None),
            ("users/create", "POST", base + "/users", {"username": "new-" + role, "enabled": True}),
            ("users/role-mappings", "GET", f"{base}/users/{target_user}/role-mappings/realm", None),
            ("clients/list", "GET", base + "/clients", None),
            ("clients/get", "GET", f"{base}/clients/{target_client}", None),
            ("clients/create", "POST", base + "/clients", {"clientId": "new-" + role, "publicClient": True}),
            ("clients/update", "PUT", f"{base}/clients/{target_client}", {"enabled": True}),
            ("roles/list", "GET", base + "/roles", None),
            ("roles/create", "POST", base + "/roles", {"name": "new-" + role}),
            ("groups/list", "GET", base + "/groups", None),
            ("groups/create", "POST", base + "/groups", {"name": "new-" + role}),
            ("other-realm/get", "GET", "/admin/realms/" + self.other, None),
            ("other-realm/users", "GET", f"/admin/realms/{self.other}/users", None),
            ("realms/list", "GET", "/admin/realms", None),
            ("realms/create", "POST", "/admin/realms", {"realm": "created-" + secrets.token_hex(4)}),
        ]
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        for label, method, path, payload in operations:
            expected = REFERENCE[f"{role}/{label}"]
            status, _, body = self.request(method, path, headers, body=json.dumps(payload) if payload is not None else None)
            parsed = json.loads(body) if body else None
            self.assertEqual(status, expected["status"], label)
            self.assertEqual(parsed.get("error") if isinstance(parsed, dict) else None, expected["error"], label)
            if "realms" in expected:
                self.assertEqual(sorted(item["realm"].replace(self.realm, "{realm}") for item in parsed), expected["realms"], label)
            brief = expected.get("fields") is not None and len(expected["fields"]) < 10
            if brief:
                fields = sorted({field for item in parsed for field in item}) if isinstance(parsed, list) else sorted(parsed)
                self.assertEqual(fields, [field for field in expected["fields"] if field != "displayName"], label)

    def test_acting_realm_admin_can_be_deleted(self):
        token = self.realm_token("realm-admin")
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        base = f"/admin/realms/{self.realm}"
        self.assertEqual(self.request("POST", base + "/users", headers, body=json.dumps({"username": "made-by-realm-admin", "enabled": True}))[0], 201)
        client = json.loads(self.call("GET", base + "/clients?clientId=sa-realm-admin")[2])[0]["id"]
        self.assertEqual(self.call("DELETE", f"{base}/clients/{client}")[0], 204)
        self.assertEqual(self.request("GET", base + "/users", headers)[0], 401)


for _role in ROLES:
    setattr(AdminPermissionsContract, "test_" + _role.replace("-", "_"), lambda self, role=_role: self.check_role(role))


if __name__ == "__main__":
    unittest.main()
