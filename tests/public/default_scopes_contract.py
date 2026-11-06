"""Default client scope claims compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/default-scope-observations.json.
Known differences, listed in IMPLEMENTATION.md: the access token here has
no `acr`, `allowed-origins` or `auth_time` and the ID token no `acr`,
`at_hash` or `jti`, so only the profile and email claims are compared.
"""

import base64
import hashlib
import json
import pathlib
import re
import secrets
import unittest
import urllib.parse

from fixture import AdminCase, b64


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/default-scope-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"
USER_CLAIMS = {"preferred_username", "email", "email_verified", "name", "given_name", "family_name"}


def payload(token):
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


class DefaultScopesContract(AdminCase):
    def setUp(self):
        super().setUp()
        base = f"/admin/realms/{self.realm}"
        self.assertEqual(self.call("POST", base + "/clients", {"clientId": "user-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        user = self.call("POST", base + "/users", {"username": "reference-user", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "reference@example.invalid", "emailVerified": True})[1]["location"].rsplit("/", 1)[1]
        self.password = secrets.token_urlsafe(30)
        self.call("PUT", f"{base}/users/{user}/reset-password", {"type": "password", "value": self.password})

    def authorize(self, scope):
        verifier = secrets.token_urlsafe(48)
        query = urllib.parse.urlencode({"client_id": "user-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": scope, "state": "state", "code_challenge": b64(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"})
        return verifier, self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/auth?{query}")

    def login(self, scope):
        verifier, (status, headers, body) = self.authorize(scope)
        self.assertEqual(status, 200)
        action = re.search(r'action="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        status, headers, _ = self.request("POST", action, {"Cookie": headers["set-cookie"].split(";", 1)[0]}, {"username": "reference-user", "password": self.password})
        return self.exchange_code(self.realm, "user-app", CALLBACK, headers["location"], verifier)

    def check(self, label, scope):
        tokens = self.login(scope)
        expected = REFERENCE[label]
        access = self.verify(tokens["access_token"])
        self.assertEqual(sorted(tokens["scope"].split()), expected["response_scope"], label)
        self.assertEqual(sorted(access["scope"].split()), expected["access_scope"], label)
        self.assertEqual("id_token" in tokens, expected["has_id_token"], label)
        self.assertEqual(sorted(USER_CLAIMS & set(access)), sorted(USER_CLAIMS & set(expected["access_claims"])), label)
        if "id_token" in tokens:
            identity = payload(tokens["id_token"])
            self.assertEqual(sorted(USER_CLAIMS & set(identity)), sorted(USER_CLAIMS & set(expected["id_claims"])), label)
            self.assertEqual({key: identity.get(key) for key in expected["values"]}, expected["values"], label)
        status, _, body = self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/userinfo", {"Authorization": "Bearer " + tokens["access_token"]})
        self.assertEqual(status, expected["userinfo_status"], label)
        if status == 200:
            self.assertEqual(sorted(json.loads(body)), expected["userinfo_claims"], label)
        return tokens

    def test_openid(self):
        self.check("scope/openid", "openid")

    def test_openid_profile_email(self):
        tokens = self.check("scope/openid-profile-email", "openid profile email")
        status, _, body = self.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token", form={"grant_type": "refresh_token", "client_id": "user-app", "refresh_token": tokens["refresh_token"]})
        self.assertEqual(status, 200, body)
        self.assertEqual(sorted(json.loads(body)["scope"].split()), REFERENCE["scope/openid-profile-email"]["response_scope"])

    def test_openid_email(self):
        self.check("scope/openid-email", "openid email")

    def test_without_openid(self):
        self.check("scope/without-openid", "profile")

    def test_unknown_scope(self):
        _, (status, headers, _) = self.authorize("openid unknown-scope")
        error = urllib.parse.parse_qs(urllib.parse.urlsplit(headers.get("location", "")).query).get("error")
        self.assertEqual({"authorize_status": status, "error": error}, REFERENCE["scope/unknown"])


if __name__ == "__main__":
    unittest.main()
