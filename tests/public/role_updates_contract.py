"""Role updates and roles-by-id compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/role-update-observations.json.
"""

import json
import pathlib
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/role-update-observations.json").read_text()
)["observations"]


class RoleUpdatesContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.base = f"/admin/realms/{self.realm}"
        for name in ("editor", "viewer", "child"):
            self.assertEqual(self.call("POST", self.base + "/roles", {"name": name, "description": "Old"})[0], 201)
        self.app = self.call("POST", self.base + "/clients", {"clientId": "role-app", "publicClient": True})[1]["location"].rsplit("/", 1)[1]
        self.assertEqual(self.call("POST", f"{self.base}/clients/{self.app}/roles", {"name": "app-role"})[0], 201)
        self.editor = json.loads(self.call("GET", self.base + "/roles/editor")[2])
        self.child = json.loads(self.call("GET", self.base + "/roles/child")[2])
        self.app_role = json.loads(self.call("GET", f"{self.base}/clients/{self.app}/roles/app-role")[2])

    def case(self, response, label):
        status, _, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        self.assertEqual(not body, expected["empty_body"], label)
        parsed = json.loads(body) if body else None
        if "body" in expected:
            self.assertEqual({key: parsed[key] for key in expected["body"] if key in parsed}, expected["body"], label)
            self.assertEqual("description" in parsed, "description" in expected["body"], label)
        if "names" in expected:
            self.assertEqual(sorted(item["name"] for item in parsed), expected["names"], label)

    def test_updates_by_name(self):
        self.case(self.call("PUT", self.base + "/roles/editor", {"name": "editor", "description": "New"}), "update/description")
        self.case(self.call("GET", self.base + "/roles/editor"), "get/after-description")
        self.case(self.call("PUT", self.base + "/roles/editor", {"description": "Nameless"}), "update/no-name")
        self.case(self.call("GET", self.base + "/roles/editor"), "get/after-no-name")
        self.case(self.call("PUT", self.base + "/roles/editor", {"name": "writer"}), "update/rename")
        self.case(self.call("GET", self.base + "/roles/editor"), "get/old-name")
        self.case(self.call("GET", self.base + "/roles/writer"), "get/new-name")
        self.case(self.call("PUT", self.base + "/roles/writer", {"name": "viewer"}), "update/rename-taken")
        self.case(self.call("PUT", self.base + "/roles/missing", {"name": "missing"}), "update/unknown")
        self.case(self.call("PUT", self.base + "/roles/writer", raw="{"), "update/malformed")
        self.case(self.call("PUT", f"{self.base}/clients/{self.app}/roles/app-role", {"name": "app-role", "description": "Client"}), "update/client-role")
        self.case(self.call("GET", f"{self.base}/clients/{self.app}/roles/app-role"), "get/client-role")

    def test_reads_by_id(self):
        # The reference reached these cases after renaming editor to writer
        # without a description and describing the client role.
        self.assertEqual(self.call("PUT", self.base + "/roles/editor", {"name": "writer"})[0], 204)
        self.assertEqual(self.call("PUT", f"{self.base}/clients/{self.app}/roles/app-role", {"name": "app-role", "description": "Client"})[0], 204)
        self.case(self.call("GET", f"{self.base}/roles-by-id/{self.editor['id']}"), "by-id/get")
        self.case(self.call("GET", f"{self.base}/roles-by-id/{self.app_role['id']}"), "by-id/get-client-role")
        self.case(self.call("GET", self.base + "/roles-by-id/00000000-0000-0000-0000-000000000000"), "by-id/unknown")

    def test_writes_by_id(self):
        by_id = f"{self.base}/roles-by-id/{self.editor['id']}"
        self.case(self.call("PUT", by_id, {"name": "author", "description": "By id"}), "by-id/update")
        self.case(self.call("GET", by_id), "by-id/after-update")
        self.case(self.call("POST", by_id + "/composites", [{"id": self.child["id"], "name": "child"}]), "by-id/add-composite")
        self.case(self.call("GET", by_id + "/composites"), "by-id/composites")
        self.case(self.call("DELETE", by_id + "/composites", [{"id": self.child["id"], "name": "child"}]), "by-id/remove-composite")
        self.case(self.call("DELETE", by_id), "by-id/delete")
        self.case(self.call("GET", by_id), "by-id/after-delete")

    def test_by_id_requires_a_token(self):
        status, _, _ = self.call("GET", f"{self.base}/roles-by-id/{self.editor['id']}", token=False)
        self.assertEqual(status, 401)

    def test_console_style_update(self):
        role = json.loads(self.call("GET", self.base + "/roles/viewer")[2])
        role["description"] = "From console"
        self.assertEqual(self.call("PUT", self.base + "/roles/viewer", role)[0], 204)
        self.assertEqual(json.loads(self.call("GET", self.base + "/roles/viewer")[2])["description"], "From console")


if __name__ == "__main__":
    unittest.main()
