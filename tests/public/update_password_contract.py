"""Temporary passwords and UPDATE_PASSWORD compared with Keycloak 26.8.1.

Expected cases come from tests/reference/update-password-observations.json.
"""

import hashlib
import json
import pathlib
import re
import secrets
import time
import unittest
import urllib.parse

from fixture import ENDPOINT, AdminCase, b64
from otp_contract import totp


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/update-password-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


class PasswordSteps:
    """Login and form steps shared by the contracts below."""

    def password_step(self, password, username="reference-user"):
        query = urllib.parse.urlencode({"client_id": "pw-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"})
        status, headers, body = self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/auth?{query}")
        self.cookie = headers["set-cookie"].split(";", 1)[0]
        action = re.search(r'action="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        return self.request("POST", action, {"Cookie": self.cookie}, {"username": username, "password": password})

    def page(self, response):
        status, headers, body = response
        if status in (302, 303):
            return {"status": status, "location_params": sorted(urllib.parse.parse_qs(urllib.parse.urlsplit(headers["location"]).query))}, None
        text = body.decode()
        form = re.search(r'<form id="([^"]+)"[^>]*action="([^"]+)"', text)
        return {"status": status, "form": form.group(1), "fields": sorted(set(re.findall(r'<input[^>]*name="([^"]+)"', text)) - {"credentialId"} | ({"credentialId"} if form.group(1) == "kc-form-login" else set()))}, form.group(2).replace("&amp;", "&")

    def submit(self, action, form):
        return self.request("POST", action, {"Cookie": self.cookie}, form)


class ReplacedPasswordContract(PasswordSteps, AdminCase):
    """A temporary password replaced, then signing in with each password.
    The realm and user are made once, and the numbered tests run in order,
    since each update hashes a password."""

    temporary, chosen = secrets.token_urlsafe(30), secrets.token_urlsafe(30)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, _, body = cls.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": cls.ADMIN, "client_secret": cls.ADMIN_SECRET})
        assert status == 200, "admin token"
        cls.token = json.loads(body)["access_token"]
        cls.realm = "contract-" + secrets.token_hex(6)
        headers = {"Authorization": "Bearer " + cls.token, "Content-Type": "application/json"}
        user = {"username": "reference-user", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "reference-user@example.invalid"}
        assert cls.request("POST", "/admin/realms", headers, body=json.dumps({"realm": cls.realm, "enabled": True}))[0] == 201
        assert cls.request("POST", f"/admin/realms/{cls.realm}/clients", headers, body=json.dumps({"clientId": "pw-app", "publicClient": True, "redirectUris": [CALLBACK]}))[0] == 201
        location = cls.request("POST", f"/admin/realms/{cls.realm}/users", headers, body=json.dumps(user))[1]["location"]
        cls.users = f"/admin/realms/{cls.realm}/users/{location.rsplit('/', 1)[1]}"

    def setUp(self):
        """The class's realm replaces the per-test realm."""

    def tearDown(self):
        """The class's realm is removed with the class."""

    @classmethod
    def tearDownClass(cls):
        cls.request("DELETE", "/admin/realms/" + cls.realm, {"Authorization": "Bearer " + cls.token})
        super().tearDownClass()

    def required_actions(self):
        return {"requiredActions": json.loads(self.call("GET", self.users)[2])["requiredActions"]}

    def test_1_temporary_password_must_be_replaced(self):
        status = self.call("PUT", self.users + "/reset-password", {"type": "password", "value": self.temporary, "temporary": True})[0]
        self.assertEqual(status, REFERENCE["admin/reset-temporary"]["status"])
        self.assertEqual(self.required_actions(), REFERENCE["admin/user-after-temporary"])
        observed, action = self.page(self.password_step(self.temporary))
        self.assertEqual(observed, REFERENCE["login/update-page"])
        observed, _ = self.page(self.submit(action, {"password-new": self.chosen, "password-confirm": self.chosen}))
        self.assertEqual(observed, REFERENCE["update/success"])
        self.assertEqual(self.required_actions(), REFERENCE["admin/user-after-update"])

    def test_2_only_the_new_password_signs_in(self):
        observed, _ = self.page(self.password_step(self.temporary))
        self.assertEqual(observed["status"], REFERENCE["login/old-password"]["status"])
        self.assertEqual(observed["form"], REFERENCE["login/old-password"]["form"])
        observed, _ = self.page(self.password_step(self.chosen))
        self.assertEqual(observed, REFERENCE["login/new-password"])


class UpdatePasswordContract(PasswordSteps, AdminCase):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "pw-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        location = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "reference-user", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "reference-user@example.invalid"})[1]["location"]
        self.users = f"/admin/realms/{self.realm}/users/{location.rsplit('/', 1)[1]}"

    def required_actions(self):
        return {"requiredActions": json.loads(self.call("GET", self.users)[2])["requiredActions"]}

    def update_page(self, temporary):
        """Sets a temporary password and signs in with it; returns the
        update page's action."""
        status = self.call("PUT", self.users + "/reset-password", {"type": "password", "value": temporary, "temporary": True})[0]
        self.assertEqual(status, REFERENCE["admin/reset-temporary"]["status"])
        self.assertEqual(self.required_actions(), REFERENCE["admin/user-after-temporary"])
        observed, action = self.page(self.password_step(temporary))
        self.assertEqual(observed, REFERENCE["login/update-page"])
        return action

    def test_temporary_password_refuses_bad_updates(self):
        chosen = secrets.token_urlsafe(30)
        action = self.update_page(secrets.token_urlsafe(30))
        observed, action = self.page(self.submit(action, {"password-new": chosen, "password-confirm": chosen + "x"}))
        self.assertEqual(observed, REFERENCE["update/mismatch"])
        observed, action = self.page(self.submit(action, {"password-new": "", "password-confirm": ""}))
        self.assertEqual(observed, REFERENCE["update/empty"])

    def test_pending_update_issues_no_sso_cookie(self):
        self.call("PUT", self.users + "/reset-password", {"type": "password", "value": "temporary-password-value", "temporary": True})
        status, headers, _ = self.password_step("temporary-password-value")
        self.assertEqual(status, 200)
        self.assertNotIn("KEYCLOAK_IDENTITY", headers.get("set-cookie", ""))

    def test_totp_setup_comes_before_the_password_update(self):
        created = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "both-steps", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "both-steps@example.invalid", "requiredActions": ["CONFIGURE_TOTP"]})
        user = created[1]["location"].rsplit("/", 1)[1]
        self.call("PUT", f"/admin/realms/{self.realm}/users/{user}/reset-password", {"type": "password", "value": "temporary-password-value", "temporary": True})
        query = urllib.parse.urlencode({"client_id": "pw-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"})
        status, headers, body = self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/auth?{query}")
        self.cookie = headers["set-cookie"].split(";", 1)[0]
        action = re.search(r'action="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        response = self.request("POST", action, {"Cookie": self.cookie}, {"username": "both-steps", "password": "temporary-password-value"})
        observed, action = self.page(response)
        self.assertEqual(observed["form"], "kc-totp-settings-form")
        secret = re.search(r'name="totpSecret" value="([^"]+)"', response[2].decode()).group(1)
        observed, action = self.page(self.submit(action, {"totp": totp(secret, time.time()), "totpSecret": secret}))
        self.assertEqual(observed["form"], "kc-passwd-update-form")
        chosen = secrets.token_urlsafe(30)
        observed, _ = self.page(self.submit(action, {"password-new": chosen, "password-confirm": chosen}))
        self.assertEqual(observed["status"], 302)

class OtherSessionsContract(PasswordSteps, AdminCase):
    """One realm for the class, with a user per test who already holds an
    earlier session, so each test hashes only the new passwords."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, _, body = cls.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": cls.ADMIN, "client_secret": cls.ADMIN_SECRET})
        assert status == 200, "admin token"
        cls.token = json.loads(body)["access_token"]
        cls.realm = "contract-" + secrets.token_hex(6)
        headers = {"Authorization": "Bearer " + cls.token, "Content-Type": "application/json"}
        assert cls.request("POST", "/admin/realms", headers, body=json.dumps({"realm": cls.realm, "enabled": True}))[0] == 201
        assert cls.request("POST", f"/admin/realms/{cls.realm}/clients", headers, body=json.dumps({"clientId": "pw-app", "publicClient": True, "redirectUris": [CALLBACK]}))[0] == 201
        cls.held = {}
        for username in ("checkbox-user", "kept-user"):
            first = secrets.token_urlsafe(30)
            user = {"username": username, "enabled": True, "firstName": "Reference", "lastName": "User", "email": username + "@example.invalid", "credentials": [{"type": "password", "value": first, "temporary": False}]}
            location = cls.request("POST", f"/admin/realms/{cls.realm}/users", headers, body=json.dumps(user))[1]["location"]
            cls.held[username] = (f"/admin/realms/{cls.realm}/users/{location.rsplit('/', 1)[1]}", cls.code_tokens(username, first))

    @classmethod
    def code_tokens(cls, username, password):
        """Signs in through the login form with PKCE; returns the tokens."""
        verifier = secrets.token_urlsafe(48)
        challenge = b64(hashlib.sha256(verifier.encode()).digest())
        query = urllib.parse.urlencode({"client_id": "pw-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": challenge, "code_challenge_method": "S256"})
        _, headers, body = cls.request("GET", f"/realms/{cls.realm}/protocol/openid-connect/auth?{query}")
        action = re.search(r'action="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        _, headers, _ = cls.request("POST", action, {"Cookie": headers["set-cookie"].split(";", 1)[0]}, {"username": username, "password": password})
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(headers["location"]).query)["code"][0]
        status, _, body = cls.request("POST", f"/realms/{cls.realm}/protocol/openid-connect/token", form={"grant_type": "authorization_code", "code": code, "client_id": "pw-app", "redirect_uri": CALLBACK, "code_verifier": verifier})
        assert status == 200, "code exchange"
        return json.loads(body)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "realm"):
            cls.request("DELETE", "/admin/realms/" + cls.realm, {"Authorization": "Bearer " + cls.token})
        super().tearDownClass()

    def setUp(self):
        """The class's realm replaces the per-test realm."""

    def tearDown(self):
        """The class's realm is removed with the class."""

    def other_session_survives(self, username, checkbox):
        self.users, earlier = self.held[username]
        self.call("PUT", self.users + "/reset-password", {"type": "password", "value": "temporary-password-value", "temporary": True})
        _, action = self.page(self.password_step("temporary-password-value", username))
        chosen = secrets.token_urlsafe(30)
        form = {"password-new": chosen, "password-confirm": chosen}
        if checkbox:
            form["logout-sessions"] = "on"
        self.assertEqual(self.submit(action, form)[0], 302)
        status, _, body = self.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token", form={"grant_type": "refresh_token", "client_id": "pw-app", "refresh_token": earlier["refresh_token"]})
        return status == 200, json.loads(body)

    def test_logout_sessions_checkbox_ends_other_sessions(self):
        survived, body = self.other_session_survives("checkbox-user", checkbox=True)
        self.assertFalse(survived)
        self.assertEqual(body, {"error": "invalid_grant", "error_description": "Session not active"})

    def test_other_sessions_survive_without_the_checkbox(self):
        self.assertTrue(self.other_session_survives("kept-user", checkbox=False)[0])


if __name__ == "__main__":
    unittest.main()
