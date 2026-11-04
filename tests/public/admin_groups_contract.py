"""Groups and membership compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/admin-group-observations.json. The
representations omit Keycloak's `access` map until admin permissions exist.
"""

import json
import pathlib
import secrets
import unittest

from fixture import ENDPOINT, ISSUER_BASE, ServerCase, cli


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/admin-group-observations.json").read_text()
)["observations"]
RUN = secrets.token_hex(4)
ADMIN, ADMIN_SECRET = "group-admin-" + RUN, secrets.token_urlsafe(40)
MISSING = "00000000-0000-0000-0000-000000000000"


class AdminGroupsContract(ServerCase):
    @classmethod
    def provision(cls):
        assert cli("client", "add-confidential", "master", ADMIN, "https://app.example.test/cb", stdin=ADMIN_SECRET + "\n").returncode == 0
        assert cli("client", "enable-service-account", "master", ADMIN).returncode == 0
        assert cli("client", "grant-master-admin", ADMIN).returncode == 0

    def setUp(self):
        status, _, body = self.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": ADMIN, "client_secret": ADMIN_SECRET})
        self.assertEqual(status, 200)
        self.token = json.loads(body)["access_token"]
        self.realm = "groups-" + secrets.token_hex(6)
        self.assertEqual(self.call("POST", "/admin/realms", {"realm": self.realm, "enabled": True})[0], 201)
        self.groups = f"/admin/realms/{self.realm}/groups"

    def tearDown(self):
        self.call("DELETE", "/admin/realms/" + self.realm)

    def call(self, method, path, payload=None, raw=None, token=True):
        headers = {"Authorization": "Bearer " + self.token} if token else {}
        body = raw if raw is not None else (json.dumps(payload) if payload is not None else None)
        if body is not None:
            headers["Content-Type"] = "application/json"
        return self.request(method, path, headers, body=body)

    def assert_case(self, response, label):
        status, headers, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        pattern = expected.get("location_pattern")
        if pattern:
            prefix = pattern.replace("{base}", ISSUER_BASE).replace("{realm}", self.realm).removesuffix("{id}")
            self.assertTrue(headers.get("location", "").startswith(prefix), label)
        self.assertEqual(not body, expected["empty_body"], label)
        parsed = json.loads(body) if body else None
        for key, value in expected.get("body", {}).items():
            self.assertEqual(parsed.get(key), value, f"{label}: {key}")
        if "body_fields" in expected and isinstance(parsed, dict) and "error" not in parsed and "errorMessage" not in parsed:
            self.assertEqual(sorted(parsed), [f for f in expected["body_fields"] if f != "access"], label)
        if "names" in expected:
            self.assertEqual(sorted(item.get("name") or item.get("username") for item in parsed), expected["names"], label)
            if parsed and "name" in parsed[0]:
                self.assertEqual(sorted({f for item in parsed for f in item}), [f for f in expected["item_fields"] if f != "access"], label)
        return response

    def test_groups_membership_and_cascade(self):
        self.assert_case(self.call("GET", self.groups), "list/initial")
        staff = self.assert_case(self.call("POST", self.groups, {"name": "staff"}), "create/top")[1]["location"].rsplit("/", 1)[1]
        self.assert_case(self.call("POST", self.groups, {"name": "staff"}), "create/duplicate")
        self.assert_case(self.call("POST", self.groups, {}), "create/missing-name")
        self.assert_case(self.call("POST", self.groups, raw="{"), "create/malformed-json")
        self.assert_case(self.call("POST", self.groups, {"name": "x"}, token=False), "create/no-token")
        self.assert_case(self.call("POST", f"{self.groups}/{staff}/children", {"name": "engineering"}), "create/child")
        self.assert_case(self.call("POST", f"{self.groups}/{staff}/children", {"name": "engineering"}), "create/child-duplicate")
        self.assert_case(self.call("GET", self.groups), "list/after-create")
        self.assert_case(self.call("GET", self.groups + "/count"), "count")
        self.assert_case(self.call("GET", f"{self.groups}/{staff}"), "get/top")
        self.assert_case(self.call("GET", f"{self.groups}/{MISSING}"), "get/unknown")
        child = json.loads(self.assert_case(self.call("GET", f"{self.groups}/{staff}/children"), "children")[2])[0]["id"]
        self.assert_case(self.call("GET", f"{self.groups}/{child}"), "get/child")
        created = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "member", "enabled": True})
        user = created[1]["location"].replace(ISSUER_BASE, "")
        self.assert_case(self.call("GET", user + "/groups"), "membership/initial")
        self.assert_case(self.call("PUT", f"{user}/groups/{child}"), "membership/join")
        self.assert_case(self.call("PUT", f"{user}/groups/{child}"), "membership/join-repeat")
        self.assert_case(self.call("PUT", f"{user}/groups/{MISSING}"), "membership/join-unknown")
        self.assert_case(self.call("GET", user + "/groups"), "membership/after-join")
        self.assert_case(self.call("GET", f"{self.groups}/{child}/members"), "members")
        self.assert_case(self.call("DELETE", f"{user}/groups/{child}"), "membership/leave")
        self.assert_case(self.call("GET", user + "/groups"), "membership/after-leave")
        self.assert_case(self.call("DELETE", f"{self.groups}/{staff}"), "delete/top")
        self.assert_case(self.call("DELETE", f"{self.groups}/{staff}"), "delete/repeat")
        self.assert_case(self.call("GET", f"{self.groups}/{child}"), "get/child-after-parent-delete")


if __name__ == "__main__":
    unittest.main()
