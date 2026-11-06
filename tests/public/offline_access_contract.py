"""offline_access compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/offline-access-observations.json.
Known difference, listed in IMPLEMENTATION.md: the online session of an
offline login stays listed under /users/{id}/sessions, where the reference
lists none, so that case is not compared.
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
    (pathlib.Path(__file__).resolve().parents[1] / "reference/offline-access-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


def payload(token):
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


class OfflineAccessContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.base = f"/admin/realms/{self.realm}"
        self.endpoint = f"/realms/{self.realm}/protocol/openid-connect"
        self.client = self.call("POST", self.base + "/clients", {"clientId": "user-app", "publicClient": True, "redirectUris": [CALLBACK]})[1]["location"].rsplit("/", 1)[1]
        self.user = self.call("POST", self.base + "/users", {"username": "reference-user", "enabled": True})[1]["location"].rsplit("/", 1)[1]
        self.password = secrets.token_urlsafe(30)
        self.call("PUT", f"{self.base}/users/{self.user}/reset-password", {"type": "password", "value": self.password})

    def login(self, scope="openid offline_access"):
        verifier = secrets.token_urlsafe(48)
        query = urllib.parse.urlencode({"client_id": "user-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": scope, "state": "state", "code_challenge": b64(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"})
        status, headers, body = self.request("GET", f"{self.endpoint}/auth?{query}")
        self.assertEqual(status, 200)
        action = re.search(r'action="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        status, headers, _ = self.request("POST", action, {"Cookie": headers["set-cookie"].split(";", 1)[0]}, {"username": "reference-user", "password": self.password})
        return self.exchange_code(self.realm, "user-app", CALLBACK, headers["location"], verifier)

    def refresh(self, label, token):
        status, _, body = self.request("POST", self.endpoint + "/token", form={"grant_type": "refresh_token", "client_id": "user-app", "refresh_token": token})
        parsed = json.loads(body)
        observed = {"status": status, "error": parsed.get("error"), "error_description": parsed.get("error_description")}
        if status == 200:
            observed |= {"refresh_typ": payload(parsed["refresh_token"])["typ"], "refresh_expires_in": parsed["refresh_expires_in"], "scope": sorted(parsed["scope"].split())}
        self.assertEqual(observed, REFERENCE[label], label)
        return parsed

    def test_offline_login_and_refresh(self):
        tokens = self.login()
        refresh = payload(tokens["refresh_token"])
        access = self.verify(tokens["access_token"])
        observed = {"scope": sorted(tokens["scope"].split()), "refresh_typ": refresh["typ"], "refresh_has_exp": "exp" in refresh, "refresh_expires_in": tokens["refresh_expires_in"], "access_scope": sorted(access["scope"].split()), "realm_roles": sorted(role.replace(self.realm, "{realm}") for role in access["realm_access"]["roles"])}
        self.assertEqual(observed, REFERENCE["login"])
        self.refresh("refresh/first", tokens["refresh_token"])
        status, _, body = self.call("GET", f"{self.base}/users/{self.user}/offline-sessions/{self.client}")
        listed = json.loads(body)
        expected = REFERENCE["admin/offline-sessions"]
        self.assertEqual((status, len(listed), sorted({field for item in listed for field in item})), (expected["status"], expected["count"], [field for field in expected["fields"] if field != "ipAddress"]))
        status, _, body = self.call("GET", f"{self.base}/clients/{self.client}/offline-session-count")
        self.assertEqual({"status": status, "body": json.loads(body)}, REFERENCE["admin/offline-count"])

    def test_logouts_keep_offline_tokens(self):
        tokens = self.login()
        query = urllib.parse.urlencode({"id_token_hint": tokens["id_token"], "post_logout_redirect_uri": CALLBACK})
        self.assertEqual({"status": self.request("GET", f"{self.endpoint}/logout?{query}")[0]}, REFERENCE["logout/browser"])
        rotated = self.refresh("refresh/after-browser-logout", tokens["refresh_token"])
        self.assertEqual({"status": self.call("POST", f"{self.base}/users/{self.user}/logout")[0]}, REFERENCE["admin/user-logout"])
        rotated = self.refresh("refresh/after-user-logout", rotated["refresh_token"])
        # Access tokens refreshed from the offline session stay usable.
        status, _, _ = self.request("GET", self.endpoint + "/userinfo", {"Authorization": "Bearer " + rotated["access_token"]})
        self.assertEqual(status, 200)

    def test_revocation_ends_the_offline_session(self):
        tokens = self.login()
        status, _, _ = self.request("POST", self.endpoint + "/revoke", form={"token": tokens["refresh_token"], "client_id": "user-app"})
        self.assertEqual({"status": status}, REFERENCE["revoke/offline"])
        self.refresh("refresh/after-revoke", tokens["refresh_token"])

    def test_consent_removal_ends_the_offline_session(self):
        tokens = self.login()
        self.assertEqual({"status": self.call("DELETE", f"{self.base}/users/{self.user}/consents/user-app")[0]}, REFERENCE["admin/revoke-consent"])
        self.refresh("refresh/after-consent-revoke", tokens["refresh_token"])

    def test_online_login_gets_a_refresh_token(self):
        tokens = self.login("openid")
        self.assertEqual({"refresh_typ": payload(tokens["refresh_token"])["typ"], "scope": sorted(tokens["scope"].split())}, REFERENCE["login/online"])


if __name__ == "__main__":
    unittest.main()
