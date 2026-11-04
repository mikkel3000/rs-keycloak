"""Temporary passwords and UPDATE_PASSWORD compared with Keycloak 26.8.1.

Expected cases come from tests/reference/update-password-observations.json.
"""

import json
import pathlib
import re
import secrets
import time
import unittest
import urllib.parse

from fixture import AdminCase
from otp_contract import totp


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/update-password-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


class UpdatePasswordContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "pw-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        location = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "reference-user", "enabled": True})[1]["location"]
        self.users = f"/admin/realms/{self.realm}/users/{location.rsplit('/', 1)[1]}"

    def password_step(self, password):
        query = urllib.parse.urlencode({"client_id": "pw-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"})
        status, headers, body = self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/auth?{query}")
        self.cookie = headers["set-cookie"].split(";", 1)[0]
        action = re.search(r'action="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        return self.request("POST", action, {"Cookie": self.cookie}, {"username": "reference-user", "password": password})

    def page(self, response):
        status, headers, body = response
        if status in (302, 303):
            return {"status": status, "location_params": sorted(urllib.parse.parse_qs(urllib.parse.urlsplit(headers["location"]).query))}, None
        text = body.decode()
        form = re.search(r'<form id="([^"]+)"[^>]*action="([^"]+)"', text)
        return {"status": status, "form": form.group(1), "fields": sorted(set(re.findall(r'<input[^>]*name="([^"]+)"', text)) - {"credentialId"} | ({"credentialId"} if form.group(1) == "kc-form-login" else set()))}, form.group(2).replace("&amp;", "&")

    def submit(self, action, form):
        return self.request("POST", action, {"Cookie": self.cookie}, form)

    def required_actions(self):
        return {"requiredActions": json.loads(self.call("GET", self.users)[2])["requiredActions"]}

    def test_temporary_password_must_be_replaced(self):
        temporary, chosen = secrets.token_urlsafe(30), secrets.token_urlsafe(30)
        status = self.call("PUT", self.users + "/reset-password", {"type": "password", "value": temporary, "temporary": True})[0]
        self.assertEqual(status, REFERENCE["admin/reset-temporary"]["status"])
        self.assertEqual(self.required_actions(), REFERENCE["admin/user-after-temporary"])
        observed, action = self.page(self.password_step(temporary))
        self.assertEqual(observed, REFERENCE["login/update-page"])
        observed, action = self.page(self.submit(action, {"password-new": chosen, "password-confirm": chosen + "x"}))
        self.assertEqual(observed, REFERENCE["update/mismatch"])
        observed, action = self.page(self.submit(action, {"password-new": "", "password-confirm": ""}))
        self.assertEqual(observed, REFERENCE["update/empty"])
        observed, _ = self.page(self.submit(action, {"password-new": chosen, "password-confirm": chosen}))
        self.assertEqual(observed, REFERENCE["update/success"])
        self.assertEqual(self.required_actions(), REFERENCE["admin/user-after-update"])
        observed, _ = self.page(self.password_step(temporary))
        self.assertEqual(observed["status"], REFERENCE["login/old-password"]["status"])
        self.assertEqual(observed["form"], REFERENCE["login/old-password"]["form"])
        observed, _ = self.page(self.password_step(chosen))
        self.assertEqual(observed, REFERENCE["login/new-password"])

    def test_pending_update_issues_no_sso_cookie(self):
        self.call("PUT", self.users + "/reset-password", {"type": "password", "value": "temporary-password-value", "temporary": True})
        status, headers, _ = self.password_step("temporary-password-value")
        self.assertEqual(status, 200)
        self.assertNotIn("KEYCLOAK_IDENTITY", headers.get("set-cookie", ""))

    def test_totp_setup_comes_before_the_password_update(self):
        created = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "both-steps", "enabled": True, "requiredActions": ["CONFIGURE_TOTP"]})
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


if __name__ == "__main__":
    unittest.main()
