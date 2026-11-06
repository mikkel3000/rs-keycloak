"""Admin user search compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/user-search-observations.json. The
brief form here has no `access` field, which this server does not model.
"""

import json
import pathlib
import sys
import unittest
import urllib.parse

from fixture import AdminCase

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
from user_search import COUNTS, QUERIES, USERS  # noqa: E402


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/user-search-observations.json").read_text()
)["observations"]


class UserSearchContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.users = f"/admin/realms/{self.realm}/users"
        for user in USERS:
            self.assertEqual(self.call("POST", self.users, user)[0], 201, user["username"])

    def check_searches(self, queries):
        for label, params in queries:
            status, _, body = self.call("GET", self.users + "?" + urllib.parse.urlencode(params))
            parsed = json.loads(body)
            observed = {"status": status, "usernames": [item["username"] for item in parsed]}
            expected = dict(REFERENCE[label])
            if label == "brief":
                observed["fields"] = sorted(parsed[0])
                expected["fields"] = [field for field in expected["fields"] if field != "access"]
            self.assertEqual(observed, expected, label)

    def test_search_parameter(self):
        self.check_searches([query for query in QUERIES if query[0].startswith("search")])

    def test_field_filters(self):
        self.check_searches([query for query in QUERIES if not query[0].startswith("search")])

    def test_counts(self):
        for label, params in COUNTS:
            status, _, body = self.call("GET", self.users + "/count?" + urllib.parse.urlencode(params))
            self.assertEqual({"status": status, "value": json.loads(body)}, REFERENCE[label], label)

    def test_wildcards_in_values_are_literal(self):
        status, _, body = self.call("GET", self.users + "?" + urllib.parse.urlencode({"email": "%"}))
        self.assertEqual((status, json.loads(body)), (200, []))


if __name__ == "__main__":
    unittest.main()
