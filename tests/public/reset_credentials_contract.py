"""Forgot-password from the login page compared with Keycloak 26.8.1.

Expected cases come from tests/reference/reset-credentials-observations.json;
mail is received by the in-memory SMTP sink in tests/smtp_sink.py. Link query
parameters differ: only `key` is sent, where the reference adds its own
login-session parameters.
"""

import json
import pathlib
import re
import secrets
import sys
import unittest
import urllib.parse

from fixture import ISSUER_BASE, AdminCase

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from smtp_sink import SmtpSink  # noqa: E402


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/reset-credentials-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


class ResetCredentialsContract(AdminCase):
    @classmethod
    def setUpClass(cls):
        cls.sink = SmtpSink().__enter__()
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.sink.__exit__(None, None, None)

    def setUp(self):
        super().setUp()
        smtp = {"host": "127.0.0.1", "port": str(self.sink.port), "from": "noreply@example.invalid", "fromDisplayName": "Reference Realm"}
        self.assertEqual(self.call("PUT", f"/admin/realms/{self.realm}", {"smtpServer": smtp, "resetPasswordAllowed": True})[0], 204)
        self.assertEqual(self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "reset-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "reference-user", "enabled": True, "email": "reference@example.invalid"})
        self.sink.received.clear()

    def login_page(self, realm=None):
        query = urllib.parse.urlencode({"client_id": "reset-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"})
        status, headers, body = self.request("GET", f"/realms/{realm or self.realm}/protocol/openid-connect/auth?{query}")
        self.cookie = headers["set-cookie"].split(";", 1)[0]
        return body.decode()

    def reset_link(self, html):
        match = re.search(r'href="([^"]*login-actions/reset-credentials[^"]*)"', html)
        return match.group(1).replace("&amp;", "&") if match else None

    def summarize(self, response):
        status, headers, body = response
        if status in (302, 303):
            return {"status": status, "location_params": sorted(urllib.parse.parse_qs(urllib.parse.urlsplit(headers["location"]).query))}, None
        text = body.decode()
        form = re.search(r'<form id="([^"]+)"[^>]*action="([^"]+)"', text)
        if not form:
            return {"status": status, "form": None, "fields": []}, None
        fields = sorted(set(re.findall(r'<input[^>]*name="([^"]+)"', text)))
        if form.group(1) == "kc-form-login":
            fields = sorted(set(fields) | {"credentialId"})
        return {"status": status, "form": form.group(1), "fields": fields}, form.group(2).replace("&amp;", "&")

    def request_reset(self, username):
        link = self.reset_link(self.login_page())
        observed, action = self.summarize(self.request("GET", link, {"Cookie": self.cookie}))
        response = self.request("POST", action, {"Cookie": self.cookie}, {"username": username})
        observed_after, _ = self.summarize(response)
        observed_after["sent_text"] = "you should receive an email" in response[2].decode().lower()
        return observed, observed_after

    def test_link_only_when_allowed(self):
        self.assertEqual({"link": self.reset_link(self.login_page()) is not None}, {"link": REFERENCE["open/login-has-link"]["link"]})
        self.assertEqual(urllib.parse.urlsplit(self.reset_link(self.login_page())).path.replace(self.realm, "{realm}"), REFERENCE["open/login-has-link"]["path"])
        self.call("PUT", f"/admin/realms/{self.realm}", {"resetPasswordAllowed": False})
        self.assertEqual({"link": self.reset_link(self.login_page()) is not None}, REFERENCE["closed/login-has-link"])

    def test_unknown_user_looks_the_same_and_gets_no_mail(self):
        form, after = self.request_reset("nobody-here")
        self.assertEqual(form, REFERENCE["request/form"])
        self.assertEqual(after, REFERENCE["request/unknown-user"])
        self.assertEqual({"count": len(self.sink.received)}, REFERENCE["mail/after-unknown"])

    def test_known_user_resets_and_continues_the_login(self):
        _, after = self.request_reset("reference-user")
        self.assertEqual(after, REFERENCE["request/known-user"])
        received = self.sink.wait(1)[-1]
        message = received["message"]
        text = message.get_body(preferencelist=("plain",)).get_content()
        link = next(url for url in re.findall(r"https?://\S+", text) if "/login-actions/action-token" in url)
        expected = REFERENCE["mail/message"]
        self.assertEqual((received["to"], str(message["From"]), str(message["Subject"]), sorted(p.get_content_type() for p in message.walk() if not p.is_multipart())), (expected["to"], expected["from_header"], expected["subject"], expected["parts"]))
        self.assertEqual(urllib.parse.urlsplit(link).path.replace(self.realm, "{realm}"), expected["link_path"])
        path = link.removeprefix(ISSUER_BASE)
        observed, action = self.summarize(self.request("GET", path, {"Cookie": self.cookie}))
        self.assertEqual(observed, REFERENCE["link/first-page"])
        chosen = secrets.token_urlsafe(30)
        observed, _ = self.summarize(self.request("POST", action, {"Cookie": self.cookie}, {"password-new": chosen, "password-confirm": chosen}))
        self.assertEqual(observed, REFERENCE["link/after-update"])
        self.assertEqual(self.summarize(self.request("GET", path))[0]["status"], REFERENCE["link/reused"]["status"])
        tokens = self.browser_login(self.realm, "reset-app", CALLBACK, "reference-user", chosen)
        self.assertEqual({"signed_in": bool(tokens.get("access_token"))}, REFERENCE["login/new-password"])


if __name__ == "__main__":
    unittest.main()
