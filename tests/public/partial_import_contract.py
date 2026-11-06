"""Realm partial import compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/partial-import-observations.json.
Known differences, listed in IMPLEMENTATION.md: an overwrite does not also
count the realm role as added, imported users get the realm's default
role like any other new user, malformed JSON answers 400 rather than 500,
and groups are refused with 400 rather than failing with 500.
"""

import json
import pathlib
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/partial-import-observations.json").read_text()
)["observations"]
PAYLOAD = {
    "roles": {"realm": [{"name": "imported-role", "description": "From import"}]},
    "clients": [{"clientId": "imported-app", "publicClient": True, "redirectUris": ["https://app.example.invalid/cb"]}],
    "users": [{"username": "imported-user", "enabled": True, "email": "imported@example.invalid"}],
}


class PartialImportContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.base = f"/admin/realms/{self.realm}"

    def summary(self, response):
        status, _, body = response
        parsed = json.loads(body)
        if "results" not in parsed:
            return {"status": status, "body": parsed}
        return {"status": status, "added": parsed["added"], "skipped": parsed["skipped"], "overwritten": parsed["overwritten"], "fields": sorted(parsed), "result_fields": sorted({field for item in parsed["results"] for field in item}), "results": sorted([item["action"], item["resourceType"], item["resourceName"]] for item in parsed["results"])}

    def import_(self, policy, payload=PAYLOAD):
        return self.summary(self.call("POST", self.base + "/partialImport", dict(payload, ifResourceExists=policy)))

    def test_fail_policy(self):
        self.assertEqual(self.import_("FAIL"), REFERENCE["import/fail"])
        user = json.loads(self.call("GET", self.base + "/users?username=imported-user&exact=true")[2])[0]
        self.assertEqual(user.get("email"), REFERENCE["after/user"]["email"])
        self.assertEqual({"description": json.loads(self.call("GET", self.base + "/roles/imported-role")[2]).get("description")}, REFERENCE["after/role"])
        client = json.loads(self.call("GET", self.base + "/clients?clientId=imported-app")[2])[0]
        self.assertEqual({"public": client["publicClient"], "redirects": client["redirectUris"]}, REFERENCE["after/client"])
        self.assertEqual(self.import_("FAIL"), REFERENCE["import/fail-again"])

    def test_skip_and_overwrite(self):
        self.assertEqual(self.call("POST", self.base + "/partialImport", PAYLOAD)[0], 200)
        self.assertEqual(self.import_("SKIP"), REFERENCE["import/skip"])
        changed = json.loads(json.dumps(PAYLOAD))
        changed["roles"]["realm"][0]["description"] = "Overwritten"
        changed["users"][0]["email"] = "overwritten@example.invalid"
        expected = dict(REFERENCE["import/overwrite"])
        expected["results"] = [row for row in expected["results"] if row[0] != "ADDED"]
        expected["added"] = 0
        self.assertEqual(self.import_("OVERWRITE", changed), expected)
        user = json.loads(self.call("GET", self.base + "/users?username=imported-user&exact=true")[2])[0]
        role = json.loads(self.call("GET", self.base + "/roles/imported-role")[2])
        self.assertEqual({"role_description": role.get("description"), "email": user.get("email")}, REFERENCE["after-overwrite"])

    def test_empty_malformed_and_groups(self):
        self.assertEqual(self.summary(self.call("POST", self.base + "/partialImport", {})), REFERENCE["import/empty"])
        self.assertEqual(self.call("POST", self.base + "/partialImport", raw="{")[0], 400)
        self.assertEqual(self.call("POST", self.base + "/partialImport", {"groups": [{"name": "imported-group"}]})[0], 400)

    def test_failed_import_changes_nothing(self):
        self.assertEqual(self.call("POST", self.base + "/clients", {"clientId": "imported-app", "publicClient": True})[0], 201)
        self.assertEqual(self.import_("FAIL")["status"], 409)
        self.assertEqual(self.call("GET", self.base + "/roles/imported-role")[0], 404)


if __name__ == "__main__":
    unittest.main()
