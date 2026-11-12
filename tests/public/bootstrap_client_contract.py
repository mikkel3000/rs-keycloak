"""Bootstrap admin client with the upstream test framework's credentials.

The framework signs in to the master realm with client credentials of a
client whose secret is `mysecret`, as `KC_BOOTSTRAP_ADMIN_CLIENT_SECRET`
sets it on a `start-dev` reference server. Local development accepts such
short secrets; these tests run with RS_KEYCLOAK_LOCAL_DEV=true.
"""

import json
import os
import secrets
import unittest

from fixture import ENDPOINT, ServerCase, cli


CLIENT = "temp-admin-" + secrets.token_hex(4)
SECRET = "mysecret"


class BootstrapClientContract(ServerCase):
    @classmethod
    def provision(cls):
        assert os.environ.get("RS_KEYCLOAK_LOCAL_DEV") == "true", "RS_KEYCLOAK_LOCAL_DEV=true is required"
        result = cli("client", "add-confidential", "master", CLIENT, "http://localhost:8080/cb", stdin=SECRET + "\n")
        assert result.returncode == 0, result.stderr
        assert cli("client", "enable-service-account", "master", CLIENT).returncode == 0
        assert cli("client", "grant-master-admin", CLIENT).returncode == 0

    def test_short_secret_signs_in_to_the_admin_api(self):
        status, _, body = self.request("POST", ENDPOINT + "/token", form={
            "grant_type": "client_credentials", "client_id": CLIENT, "client_secret": SECRET,
        })
        self.assertEqual(status, 200)
        token = json.loads(body)["access_token"]
        status, _, body = self.request("GET", "/admin/realms/master", {"Authorization": "Bearer " + token})
        self.assertEqual((status, json.loads(body)["realm"]), (200, "master"))

    def test_empty_secret_is_refused(self):
        result = cli("client", "add-confidential", "master", CLIENT + "-empty", "http://localhost:8080/cb", stdin="\n")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
