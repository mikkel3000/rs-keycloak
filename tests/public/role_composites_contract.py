"""Composite role editing compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/role-composite-observations.json.
"""

import json
import pathlib
import secrets
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/role-composite-observations.json").read_text()
)["observations"]


class RoleCompositesContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.base = f"/admin/realms/{self.realm}"
        self.secret = secrets.token_urlsafe(40)
        for name in ("parent", "child", "grandchild"):
            self.assertEqual(self.call("POST", self.base + "/roles", {"name": name})[0], 201)
        status, headers, _ = self.call("POST", self.base + "/clients", {"clientId": "holder-app", "secret": self.secret, "serviceAccountsEnabled": True, "standardFlowEnabled": False})
        self.assertEqual(status, 201)
        self.app = headers["location"].rsplit("/", 1)[1]
        for name in ("app-child", "app-parent"):
            self.assertEqual(self.call("POST", f"{self.base}/clients/{self.app}/roles", {"name": name})[0], 201)
        self.roles = {name: json.loads(self.call("GET", f"{self.base}/roles/{name}")[2]) for name in ("parent", "child", "grandchild")}
        self.roles["app-child"] = json.loads(self.call("GET", f"{self.base}/clients/{self.app}/roles/app-child")[2])
        self.holder = json.loads(self.call("GET", f"{self.base}/clients/{self.app}/service-account-user")[2])["id"]
        self.assertEqual(self.call("POST", f"{self.base}/users/{self.holder}/role-mappings/realm", self.ref("parent"))[0], 204)

    def ref(self, name):
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

    def claims(self, label):
        status, _, body = self.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token", form={"grant_type": "client_credentials", "client_id": "holder-app", "client_secret": self.secret})
        self.assertEqual(status, 200)
        claims = self.verify(json.loads(body)["access_token"])
        observed = {
            "realm_access": sorted(name.replace(self.realm, "{realm}") for name in claims.get("realm_access", {}).get("roles", [])),
            "resource_access": sorted(claims.get("resource_access", {}).get("holder-app", {}).get("roles", [])),
        }
        self.assertEqual(observed, REFERENCE[label], label)

    def add_children(self):
        composites = f"{self.base}/roles/parent/composites"
        self.case(self.call("POST", composites, self.ref("child")), "add/realm-child")
        self.case(self.call("POST", composites, self.ref("app-child")), "add/client-child")
        self.case(self.call("POST", f"{self.base}/roles/child/composites", self.ref("grandchild")), "add/grandchild")
        self.case(self.call("POST", composites, self.ref("child")), "add/repeat")

    def test_editing_errors(self):
        self.add_children()
        composites = f"{self.base}/roles/parent/composites"
        self.case(self.call("POST", composites, [{"id": "00000000-0000-0000-0000-000000000000", "name": "missing"}]), "add/unknown-role")
        self.case(self.call("POST", f"{self.base}/roles/missing/composites", self.ref("child")), "add/unknown-parent")
        self.case(self.call("POST", composites, self.ref("parent")), "add/self")
        self.case(self.call("POST", f"{self.base}/roles/grandchild/composites", self.ref("parent")), "add/cycle")
        self.case(self.call("POST", f"{self.base}/clients/{self.app}/roles/app-parent/composites", self.ref("child")), "add/client-parent")
        self.case(self.call("POST", composites, {"name": "child"}), "add/malformed")

    def test_listings_removal_and_creation(self):
        composites = f"{self.base}/roles/parent/composites"
        # The direct children the reference listings saw, including its
        # self-inclusion case.
        self.assertEqual(self.call("POST", composites, self.ref("child") + self.ref("app-child") + self.ref("parent"))[0], 204)
        self.case(self.call("GET", f"{self.base}/roles/parent"), "get/parent")
        self.case(self.call("GET", composites), "list/composites")
        self.case(self.call("GET", composites + "/realm"), "list/realm-composites")
        self.case(self.call("GET", f"{composites}/clients/{self.app}"), "list/client-composites")
        self.case(self.call("DELETE", composites, self.ref("child")), "remove/child")
        self.case(self.call("GET", composites), "list/after-remove")
        self.case(self.call("DELETE", composites, self.ref("app-child")), "remove/last")
        self.assertEqual(json.loads(self.call("GET", f"{self.base}/roles/parent")[2])["composite"], REFERENCE["get/after-remove-last"]["composite"])
        self.case(self.call("POST", self.base + "/roles", {"name": "born-composite", "composite": True, "composites": {"realm": ["child"]}}), "create/composite")
        self.case(self.call("GET", f"{self.base}/roles/born-composite/composites"), "get/born-composite")

    def test_tokens_follow_composites(self):
        self.claims("token/before")
        self.add_children()
        self.case(self.call("GET", f"{self.base}/users/{self.holder}/role-mappings/realm/composite"), "user/effective")
        self.claims("token/after-add")
        self.assertEqual(self.call("DELETE", f"{self.base}/roles/parent/composites", self.ref("child"))[0], 204)
        self.claims("token/after-remove")

    def test_unknown_composite_at_creation_creates_nothing(self):
        status, _, _ = self.call("POST", self.base + "/roles", {"name": "broken", "composites": {"realm": ["missing"]}})
        self.assertEqual(status, 404)
        self.assertEqual(self.call("GET", f"{self.base}/roles/broken")[0], 404)


if __name__ == "__main__":
    unittest.main()
