"""Client-credentials grant compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/service-account-observations.json.
Known differences, listed in IMPLEMENTATION.md: access tokens use the client as
audience and only `openid` is grantable, so scope and audience values differ.
"""

import base64
import json
import pathlib
import secrets
import unittest

from fixture import ENDPOINT, ServerCase, cli


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/service-account-observations.json").read_text()
)["observations"]
REGISTERED = "https://registered.example.invalid"
RUN = secrets.token_hex(4)
OWNER = "service-owner-" + RUN
PLAIN = "service-disabled-" + RUN
PUBLIC = "service-public-" + RUN
SECRET = secrets.token_urlsafe(40)
PLAIN_SECRET = secrets.token_urlsafe(40)


class ClientCredentialsContract(ServerCase):
    @classmethod
    def provision(cls):
        callback = REGISTERED + "/callback"
        for client, secret in ((OWNER, SECRET), (PLAIN, PLAIN_SECRET)):
            result = cli("client", "add-confidential", "master", client, callback, stdin=secret + "\n")
            assert result.returncode == 0, "Confidential client setup failed"
        assert cli("client", "add-public", "master", PUBLIC, callback).returncode == 0
        for _ in range(2):
            assert cli("client", "enable-service-account", "master", OWNER).returncode == 0
        assert cli("client", "enable-service-account", "master", PUBLIC).returncode != 0
        assert cli("client", "add-web-origin", "master", OWNER, REGISTERED).returncode == 0

    def grant(self, form=None, headers=None):
        return self.request("POST", ENDPOINT + "/token", headers, dict({"grant_type": "client_credentials"}, **(form or {})))

    def owner(self, **extra):
        return dict({"client_id": OWNER, "client_secret": SECRET}, **extra)

    def assert_error(self, response, label):
        status, headers, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        self.assertEqual(json.loads(body), expected["body"], label)
        self.assertEqual(headers.get("cache-control"), expected["cache_control"], label)
        self.assertEqual(headers.get("pragma"), expected["pragma"], label)

    def assert_grant(self, response, label):
        status, headers, body = response
        expected = REFERENCE[label]
        self.assertEqual(status, 200, label)
        self.assertEqual(headers.get("cache-control"), expected["cache_control"])
        self.assertEqual(headers.get("pragma"), expected["pragma"])
        tokens = json.loads(body)
        self.assertEqual(sorted(tokens), expected["response_fields"], label)
        self.assertEqual(tokens["token_type"], expected["token_type"])
        self.assertEqual(tokens["refresh_expires_in"], expected["refresh_expires_in"])
        claims = self.verify(tokens["access_token"])
        self.assertEqual(claims["typ"], expected["access_typ"])
        self.assertNotIn("sid", expected["access_claims"])
        self.assertNotIn("sid", claims)
        self.assertEqual(claims["azp"], OWNER)
        self.assertIn("realm_access", expected["access_claims"])
        self.assertEqual(claims["realm_access"]["roles"], ["default-roles-master", "offline_access", "uma_authorization"])
        if "id_token" in tokens:
            id_claims = self.verify(tokens["id_token"])
            self.assertNotIn("auth_time", expected["id_claims"])
            self.assertNotIn("auth_time", id_claims)
        return tokens

    def test_post_secret_grant_matches_reference_shape(self):
        self.assert_grant(self.grant(self.owner()), "grant/post-secret")

    def test_basic_secret_grant_matches_reference_shape(self):
        basic = base64.b64encode(f"{OWNER}:{SECRET}".encode()).decode()
        self.assert_grant(self.grant(headers={"Authorization": "Basic " + basic}), "grant/basic-secret")

    def test_openid_scope_adds_id_token(self):
        tokens = self.assert_grant(self.grant(self.owner(scope="openid")), "grant/openid-scope")
        self.assertEqual(tokens["scope"], "openid")

    def test_unknown_scope_matches_reference(self):
        self.assert_error(self.grant(self.owner(scope="unknown-scope")), "grant/unknown-scope")

    def test_wrong_secret_matches_reference(self):
        self.assert_error(self.grant({"client_id": OWNER, "client_secret": secrets.token_urlsafe(40)}), "grant/wrong-secret")

    def test_service_accounts_disabled_matches_reference(self):
        self.assert_error(self.grant({"client_id": PLAIN, "client_secret": PLAIN_SECRET}), "grant/service-accounts-disabled")

    def test_public_client_matches_reference(self):
        self.assert_error(self.grant({"client_id": PUBLIC}), "grant/public-client")

    def test_no_client_matches_reference(self):
        self.assert_error(self.grant(), "grant/no-client")

    def test_registered_origin_matches_reference(self):
        status, headers, _ = self.grant(self.owner(), {"Origin": REGISTERED})
        expected = REFERENCE["grant/registered-origin"]
        self.assertEqual(status, expected["status"])
        self.assertEqual(headers.get("access-control-allow-origin"), expected["cors"]["Access-Control-Allow-Origin"])

    def test_unregistered_origin_matches_reference(self):
        self.assert_error(self.grant(self.owner(), {"Origin": "https://unregistered.example.invalid"}), "grant/unregistered-origin")

    def test_userinfo_requires_openid_scope(self):
        token = json.loads(self.grant(self.owner())[2])["access_token"]
        status, headers, _ = self.request("GET", ENDPOINT + "/userinfo", {"Authorization": "Bearer " + token})
        expected = REFERENCE["effects/userinfo"]
        self.assertEqual(status, expected["status"])
        self.assertEqual(headers.get("www-authenticate"), expected["www_authenticate"].replace("{realm}", "master"))

    def test_revocation_ends_userinfo_but_not_new_grants(self):
        token = json.loads(self.grant(self.owner(scope="openid"))[2])["access_token"]
        userinfo = lambda: self.request("GET", ENDPOINT + "/userinfo", {"Authorization": "Bearer " + token})
        self.assertEqual(userinfo()[0], REFERENCE["effects/userinfo-openid-before-revoke"]["status"])
        status, _, body = self.request("POST", ENDPOINT + "/revoke", form=self.owner(token=token))
        self.assertEqual((status, body), (REFERENCE["effects/revoke-openid-access"]["status"], b""))
        status, headers, _ = userinfo()
        expected = REFERENCE["effects/userinfo-after-revoke"]
        self.assertEqual(status, expected["status"])
        self.assertEqual(headers.get("www-authenticate"), expected["www_authenticate"].replace("{realm}", "master"))
        self.assertEqual(self.grant(self.owner())[0], REFERENCE["effects/grant-after-revoke"]["status"])

    def test_introspection_follows_revocation(self):
        token = json.loads(self.grant(self.owner())[2])["access_token"]
        introspect = lambda: json.loads(self.request("POST", ENDPOINT + "/token/introspect", form=self.owner(token=token))[2])
        # The reference fixture token is inactive before revocation only because
        # its audience is "account"; our tokens name the client as audience.
        before = introspect()
        self.assertTrue(before["active"])
        self.assertEqual(before["username"], "service-account-" + OWNER)
        self.assertNotIn("sid", before)
        self.request("POST", ENDPOINT + "/revoke", form=self.owner(token=token))
        self.assertEqual(introspect(), REFERENCE["effects/introspect-after-revoke"]["body"])


if __name__ == "__main__":
    unittest.main()
