"""Client authentication errors compared with recorded Keycloak 26.8.1 cases.

Expected bodies come from tests/reference/token-observations.json and
tests/reference/service-account-observations.json. Run with a built binary path.
"""

import json
import pathlib
import unittest

from fixture import ENDPOINT, ServerCase


REFERENCE = pathlib.Path(__file__).resolve().parents[1] / "reference"


def recorded(name, label):
    return json.loads((REFERENCE / name).read_text())["observations"][label]


class ClientErrorsContract(ServerCase):
    def assert_recorded(self, response, expected):
        status, headers, body = response
        self.assertEqual(status, expected["status"])
        self.assertEqual(json.loads(body), expected["body"])
        self.assertEqual(headers.get("www-authenticate"), expected["www_authenticate"])

    def test_revocation_without_client_matches_reference(self):
        self.assert_recorded(
            self.request("POST", ENDPOINT + "/revoke", form={"token": "not-a-token"}),
            recorded("token-observations.json", "revoke/no-client"),
        )

    def test_token_without_client_matches_reference(self):
        # Keycloak authenticates the client before grant processing, so the
        # recorded client-credentials case applies to every grant type.
        self.assert_recorded(
            self.request("POST", ENDPOINT + "/token", form={"grant_type": "refresh_token", "refresh_token": "x"}),
            recorded("service-account-observations.json", "grant/no-client"),
        )


if __name__ == "__main__":
    unittest.main()
