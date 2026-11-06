"""Client scopes compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/client-scope-observations.json.
Known difference, listed in IMPLEMENTATION.md: only the four scopes this
server performs (basic, email, profile and roles) are listed, all default,
without protocol mappers, and there are no optional scopes.
"""

import json
import pathlib
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/client-scope-observations.json").read_text()
)["observations"]
PERFORMED = {"basic", "email", "profile", "roles"}


class ClientScopesContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.base = f"/admin/realms/{self.realm}"

    def get(self, path):
        status, _, body = self.call("GET", self.base + path)
        return status, json.loads(body)

    def test_scope_listing_and_reading(self):
        status, scopes = self.get("/client-scopes")
        expected = REFERENCE["client-scopes"]
        self.assertEqual(status, expected["status"])
        self.assertEqual(sorted([item["name"], item["protocol"], item["attributes"]["include.in.token.scope"], item["attributes"]["display.on.consent.screen"]] for item in scopes), [row for row in expected["scopes"] if row[0] in PERFORMED])
        self.assertEqual(sorted({field for item in scopes for field in item}), [field for field in expected["fields"] if field != "protocolMappers"])
        profile = next(item for item in scopes if item["name"] == "profile")
        status, one = self.get(f"/client-scopes/{profile['id']}")
        self.assertEqual((status, one), (200, profile))
        self.assertEqual(dict(zip(("status", "body"), self.get("/client-scopes/00000000-0000-0000-0000-000000000000"))), REFERENCE["client-scope/unknown"])
        # Identifiers are stable across requests.
        self.assertEqual(self.get("/client-scopes")[1], scopes)

    def test_default_lists(self):
        status, defaults = self.get("/default-default-client-scopes")
        self.assertEqual((status, sorted(item["name"] for item in defaults)), (REFERENCE["realm/default-default"]["status"], sorted(PERFORMED & set(REFERENCE["realm/default-default"]["names"]))))
        self.assertEqual(sorted({field for item in defaults for field in item}), REFERENCE["realm/default-default"]["fields"])
        self.assertEqual(self.get("/default-optional-client-scopes"), (200, []))
        client = self.call("POST", self.base + "/clients", {"clientId": "scoped-app", "publicClient": True})[1]["location"].rsplit("/", 1)[1]
        status, defaults = self.get(f"/clients/{client}/default-client-scopes")
        expected = REFERENCE["client/default"]
        self.assertEqual((status, sorted(item["name"] for item in defaults)), (expected["status"], sorted(PERFORMED & set(expected["names"]))))
        self.assertEqual(sorted({field for item in defaults for field in item}), expected["fields"])
        self.assertEqual(self.get(f"/clients/{client}/optional-client-scopes"), (200, []))
        self.assertEqual(dict(zip(("status", "body"), self.get("/clients/00000000-0000-0000-0000-000000000000/default-client-scopes"))), REFERENCE["client/unknown"])
        representation = self.get(f"/clients/{client}")[1]
        self.assertEqual(sorted(representation["defaultClientScopes"]), sorted(PERFORMED & set(REFERENCE["client/representation"]["default"])))


if __name__ == "__main__":
    unittest.main()
