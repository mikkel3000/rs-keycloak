"""Group renames and moves compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/group-update-observations.json.
Known differences, listed in IMPLEMENTATION.md: a name with `/` is refused
here (the reference renamed the group to `x/y`, so later paths name it
`renamed`), and a move under the group's own subgroup answers 400 where the
reference fails with a 500.
"""

import json
import pathlib
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/group-update-observations.json").read_text()
)["observations"]


class GroupUpdatesContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.base = f"/admin/realms/{self.realm}/groups"
        self.a = self.create(self.base, "a")
        self.create(self.base, "b")
        self.child = self.create(f"{self.base}/{self.a}/children", "child")
        self.create(f"{self.base}/{self.a}/children", "sibling")
        self.loose = self.create(self.base, "loose")

    def create(self, path, name):
        status, headers, body = self.call("POST", path, {"name": name})
        self.assertEqual(status, 201, name)
        return headers["location"].rsplit("/", 1)[1] if "location" in headers else json.loads(body)["id"]

    def case(self, response, label, rename=None):
        status, _, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        self.assertEqual(not body, expected["empty_body"], label)
        parsed = json.loads(body) if body else None
        fix = lambda value: value.replace("x/y", "renamed") if isinstance(value, str) and rename else value
        if "body" in expected:
            self.assertEqual({key: parsed[key] for key in expected["body"] if key in parsed}, {key: fix(value) for key, value in expected["body"].items()}, label)
        if "names" in expected:
            self.assertEqual(sorted(item["name"] for item in parsed), sorted(fix(name) for name in expected["names"]), label)

    def test_renames(self):
        self.case(self.call("PUT", f"{self.base}/{self.a}", {"name": "renamed"}), "rename")
        self.case(self.call("GET", f"{self.base}/{self.a}"), "get/after-rename")
        self.case(self.call("GET", f"{self.base}/{self.child}"), "get/child-path")
        self.case(self.call("PUT", f"{self.base}/{self.a}", {"name": "b"}), "rename/top-level-taken")
        self.case(self.call("PUT", f"{self.base}/{self.child}", {"name": "sibling"}), "rename/sibling-taken")
        self.case(self.call("PUT", f"{self.base}/{self.a}", {}), "rename/no-name")
        self.case(self.call("PUT", f"{self.base}/00000000-0000-0000-0000-000000000000", {"name": "x"}), "rename/unknown")
        self.case(self.call("PUT", f"{self.base}/{self.a}", raw="{"), "rename/malformed")
        self.assertEqual(self.call("PUT", f"{self.base}/{self.a}", {"name": "x/y"})[0], 400)

    def test_moves(self):
        self.assertEqual(self.call("PUT", f"{self.base}/{self.a}", {"name": "renamed"})[0], 204)
        self.case(self.call("POST", f"{self.base}/{self.a}/children", {"id": self.loose, "name": "loose"}), "move/into-parent")
        self.case(self.call("GET", f"{self.base}/{self.loose}"), "get/after-move", rename=True)
        self.case(self.call("GET", self.base), "list/top-level-after-move", rename=True)
        self.case(self.call("POST", self.base, {"id": self.child, "name": "child"}), "move/to-top")
        self.case(self.call("GET", f"{self.base}/{self.child}"), "get/after-move-top")
        self.case(self.call("POST", f"{self.base}/{self.a}/children", {"id": self.a, "name": "renamed"}), "move/into-self")
        self.assertEqual(self.call("POST", f"{self.base}/{self.loose}/children", {"id": self.a, "name": "renamed"})[0], 400)

    def test_console_style_update(self):
        group = json.loads(self.call("GET", f"{self.base}/{self.a}")[2])
        group["name"] = "from-console"
        self.assertEqual(self.call("PUT", f"{self.base}/{self.a}", group)[0], 204)
        self.assertEqual(json.loads(self.call("GET", f"{self.base}/{self.a}")[2])["path"], "/from-console")


if __name__ == "__main__":
    unittest.main()
