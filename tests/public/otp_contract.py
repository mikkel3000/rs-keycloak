"""TOTP setup and login compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/otp-observations.json. The reference
waits for a new 30-second step before logging in; within the 500 ms budget this
contract instead uses the next step's code, which the one-step look-around
accepts and which is always later than the setup step.
"""

import hashlib
import hmac
import json
import pathlib
import re
import secrets
import struct
import time
import unittest
import urllib.parse

from fixture import AdminCase, class_per_test


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/otp-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


def totp(secret, at):
    """RFC 6238 with Keycloak's defaults, independent of the Rust code."""
    digest = hmac.new(secret.encode(), struct.pack(">Q", int(at // 30)), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    return str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


def wrong(secret):
    return next(code for code in ("000000", "111111", "222222") if code not in {totp(secret, time.time() + d) for d in (-30, 0, 30)})


class OtpContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "otp-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        location = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "reference-user", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "reference-user@example.invalid", "requiredActions": ["CONFIGURE_TOTP"]})[1]["location"]
        self.user = location.rsplit("/", 1)[1]
        self.password = secrets.token_urlsafe(32)
        self.call("PUT", f"/admin/realms/{self.realm}/users/{self.user}/reset-password", {"type": "password", "value": self.password})
        self.users = f"/admin/realms/{self.realm}/users/{self.user}"

    def password_step(self, jar):
        query = urllib.parse.urlencode({"client_id": "otp-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"})
        status, headers, body = self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/auth?{query}")
        jar["rs_auth"] = headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]
        action = re.search(r'action="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        return self.post(action, jar, {"username": "reference-user", "password": self.password})

    def post(self, action, jar, form):
        status, headers, body = self.request("POST", action, {"Cookie": f"rs_auth={jar['rs_auth']}"}, form)
        return status, headers, body

    def page(self, response):
        status, headers, body = response
        if status in (302, 303):
            return {"status": status, "location_params": sorted(urllib.parse.parse_qs(urllib.parse.urlsplit(headers["location"]).query))}, None
        text = body.decode()
        form = re.search(r'<form id="([^"]+)"[^>]*action="([^"]+)"', text)
        fields = sorted(set(re.findall(r'<input[^>]*name="([^"]+)"', text)))
        secret = re.search(r'name="totpSecret" value="([^"]+)"', text)
        return {"status": status, "form": form.group(1), "fields": fields}, (form.group(2).replace("&amp;", "&"), secret.group(1) if secret else None)

    def configure(self):
        jar = {}
        observed, (action, secret) = self.page(self.password_step(jar))
        self.assertEqual(observed, REFERENCE["setup/page"])
        self.assertEqual({"length": len(secret), "alphanumeric": secret.isalnum()}, REFERENCE["setup/secret"])
        observed, (action, _) = self.page(self.post(action, jar, {"totp": wrong(secret), "totpSecret": secret, "userLabel": "phone"}))
        self.assertEqual(observed, REFERENCE["setup/wrong-code"])
        observed, (action, _) = self.page(self.post(action, jar, {"totp": "", "totpSecret": secret, "userLabel": "phone"}))
        self.assertEqual(observed, REFERENCE["setup/missing-code"])
        observed, _ = self.page(self.post(action, jar, {"totp": totp(secret, time.time()), "totpSecret": secret, "userLabel": "phone"}))
        self.assertEqual(observed, REFERENCE["setup/correct-code"])
        return secret

    def test_setup_records_the_credential(self):
        secret = self.configure()
        credentials = json.loads(self.call("GET", self.users + "/credentials")[2])
        otp = next(c for c in credentials if c["type"] == "otp")
        expected = REFERENCE["admin/credentials"]
        self.assertEqual((sorted(c["type"] for c in credentials), sorted(otp), otp["userLabel"]), (expected["types"], expected["otp_fields"], expected["otp_label"]))
        self.assertNotIn(secret, json.dumps(credentials))
        rep = json.loads(self.call("GET", self.users)[2])
        self.assertEqual({"totp": rep["totp"], "requiredActions": rep["requiredActions"]}, REFERENCE["admin/user-after-setup"])

    def test_login_with_codes(self):
        secret = self.configure()
        jar = {}
        observed, (action, _) = self.page(self.password_step(jar))
        self.assertEqual(observed, REFERENCE["login/otp-page"])
        observed, (action, _) = self.page(self.post(action, jar, {"otp": wrong(secret)}))
        self.assertEqual(observed, REFERENCE["login/wrong-code"])
        code = totp(secret, time.time() + 30)
        observed, _ = self.page(self.post(action, jar, {"otp": code}))
        self.assertEqual(observed, REFERENCE["login/correct-code"])

    def test_used_code_is_refused(self):
        secret = self.configure()
        code = totp(secret, time.time() + 30)
        for label in ("login/correct-code", "login/reused-code"):
            jar = {}
            _, (action, _) = self.page(self.password_step(jar))
            observed, _ = self.page(self.post(action, jar, {"otp": code}))
            self.assertEqual(observed, REFERENCE[label], label)

    def test_deleted_credential_ends_the_second_factor(self):
        self.configure()
        otp = next(c for c in json.loads(self.call("GET", self.users + "/credentials")[2]) if c["type"] == "otp")
        self.assertEqual(self.call("DELETE", f"{self.users}/credentials/{otp['id']}")[0], REFERENCE["admin/delete-otp"]["status"])
        observed, _ = self.page(self.password_step({}))
        self.assertEqual(observed, REFERENCE["login/after-delete"])

    def test_pending_second_factor_gets_no_code_or_sso(self):
        jar = {}
        status, headers, _ = self.password_step(jar)
        self.assertEqual(status, 200)
        self.assertNotIn("KEYCLOAK_IDENTITY", headers.get("set-cookie", ""))


class_per_test(OtpContract, globals())

if __name__ == "__main__":
    unittest.main()
