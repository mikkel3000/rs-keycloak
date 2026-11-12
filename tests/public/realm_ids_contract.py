"""Realm creation with a given id, compared with recorded Keycloak 26.8.1
behavior.

Expected cases come from tests/reference/realm-id-observations.json. The
upstream test framework's RealmSupplier always sends `id`, set to the realm
name, and its realm files are larger than the 16 KiB other routes take.
"""

import json
import pathlib
import re
import secrets
import unittest

from fixture import AdminCase

REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/realm-id-observations.json").read_text()
)["observations"]

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def large_texts():
    return {"en": {f"key{index:04d}": "x" * 120 for index in range(320)}}


class RealmIdsContract(AdminCase):
    def create(self, payload):
        status, _, body = self.call("POST", "/admin/realms", payload)
        parsed = json.loads(body) if body else None
        return {"status": status, "body": parsed if isinstance(parsed, dict) and len(parsed) <= 2 else None}

    def realm_named(self, suffix):
        name = f"{self.realm}-{suffix}"
        self.addCleanup(self.call, "DELETE", "/admin/realms/" + name)
        return name

    def read(self, name):
        status, _, body = self.call("GET", "/admin/realms/" + name)
        return status, json.loads(body)

    def test_given_id(self):
        name, given = self.realm_named("given"), "id-" + secrets.token_hex(6)
        self.assertEqual(self.create({"realm": name, "id": given, "enabled": True}), REFERENCE["create/given-id"])
        status, realm = self.read(name)
        self.assertEqual({"status": status, "id_is_given": realm["id"] == given, "enabled": realm["enabled"]}, REFERENCE["read/given-id"])
        status, _, listed = self.call("GET", "/admin/realms")
        listed_with_id = any(item["realm"] == name and item["id"] == given for item in json.loads(listed))
        self.assertEqual({"status": status, "listed_with_id": listed_with_id}, REFERENCE["list/given-id"])
        status = self.call("PUT", "/admin/realms/" + name, {"realm": name, "id": "changed-" + secrets.token_hex(4), "enabled": True})[0]
        _, realm = self.read(name)
        self.assertEqual({"status": status, "id_kept": realm["id"] == given}, REFERENCE["update/other-id"])
        self.assertEqual({"status": self.call("PUT", "/admin/realms/" + name, realm)[0]}, REFERENCE["update/own-representation"])
        other = self.realm_named("other")
        self.assertEqual(self.create({"realm": other, "id": given}), REFERENCE["create/taken-id"])

    def test_reserved_and_blank_ids(self):
        other = self.realm_named("other")
        for label, value in (("semicolon", "in;valid"), ("slash", "in/valid"), ("hash", "in#valid")):
            self.assertEqual(self.create({"realm": other, "id": value}), REFERENCE[f"create/reserved-{label}"], label)
        blank = self.realm_named("blank")
        self.assertEqual(self.create({"realm": blank, "id": "  "}), REFERENCE["create/blank-id"])
        status, realm = self.read(blank)
        self.assertEqual({"status": status, "generated_uuid": bool(UUID.match(realm["id"]))}, REFERENCE["read/blank-id"])

    def test_large_representations(self):
        name, texts = self.realm_named("large"), large_texts()
        self.assertEqual(self.create({"realm": name, "enabled": True, "localizationTexts": texts}), REFERENCE["create/large"])
        status, _, body = self.call("GET", f"/admin/realms/{name}/localization/en")
        self.assertEqual({"status": status, "texts": len(json.loads(body))}, REFERENCE["read/large-texts"])
        status = self.call("PUT", "/admin/realms/" + name, {"realm": name, "displayName": "Large", "localizationTexts": texts})[0]
        _, realm = self.read(name)
        self.assertEqual({"status": status, "display_name": realm.get("displayName")}, REFERENCE["update/large"])


if __name__ == "__main__":
    unittest.main()
