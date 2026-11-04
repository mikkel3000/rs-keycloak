"""Admin execute-actions-email compared with recorded Keycloak 26.8.1.

Expected cases come from tests/reference/execute-actions-observations.json;
mail is received by the in-memory SMTP sink in tests/smtp_sink.py.
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
    (pathlib.Path(__file__).resolve().parents[1] / "reference/execute-actions-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


class ExecuteActionsContract(AdminCase):
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
        self.assertEqual(self.call("PUT", f"/admin/realms/{self.realm}", {"smtpServer": smtp})[0], 204)
        self.assertEqual(self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "mail-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        users = f"/admin/realms/{self.realm}/users"
        self.user = self.call("POST", users, {"username": "reference-user", "enabled": True, "email": "reference@example.invalid"})[1]["location"].rsplit("/", 1)[1]
        self.no_email = self.call("POST", users, {"username": "no-email", "enabled": True})[1]["location"].rsplit("/", 1)[1]
        self.sink.received.clear()

    def execute(self, user, actions, realm=None):
        status, _, body = self.call("PUT", f"/admin/realms/{realm or self.realm}/users/{user}/execute-actions-email", actions)
        return {"status": status, "body": json.loads(body) if body else None}

    def test_errors_and_settings(self):
        rep = json.loads(self.call("GET", f"/admin/realms/{self.realm}")[2])
        self.assertEqual({"fields": sorted(rep["smtpServer"])}, REFERENCE["admin/realm-smtp"])
        self.assertEqual(self.execute(self.no_email, ["UPDATE_PASSWORD"]), REFERENCE["send/no-email"])
        self.assertEqual(self.execute(self.user, ["NOT_AN_ACTION"]), REFERENCE["send/unknown-action"])
        bare = "bare-" + secrets.token_hex(4)
        self.assertEqual(self.call("POST", "/admin/realms", {"realm": bare, "enabled": True})[0], 201)
        try:
            user = self.call("POST", f"/admin/realms/{bare}/users", {"username": "u", "enabled": True, "email": "u@example.invalid"})[1]["location"].rsplit("/", 1)[1]
            self.assertEqual(self.execute(user, ["UPDATE_PASSWORD"], bare), REFERENCE["send/no-smtp"])
        finally:
            self.call("DELETE", f"/admin/realms/{bare}")
        self.assertEqual(len(self.sink.received), 0)

    def test_link_updates_the_password_once(self):
        self.assertEqual(self.execute(self.user, ["UPDATE_PASSWORD"]), REFERENCE["send/success"])
        received = self.sink.wait(1)[-1]
        message = received["message"]
        text = message.get_body(preferencelist=("plain",)).get_content()
        link = next(url for url in re.findall(r"https?://\S+", text) if "/login-actions/action-token" in url)
        parsed = urllib.parse.urlsplit(link)
        expected = REFERENCE["mail/message"]
        self.assertEqual({
            "to": received["to"], "from_header": str(message["From"]), "subject": str(message["Subject"]),
            "multipart": message.is_multipart(),
            "parts": sorted(part.get_content_type() for part in message.walk() if not part.is_multipart()),
            "link_path": parsed.path.replace(self.realm, "{realm}"),
            "link_params": sorted(urllib.parse.parse_qs(parsed.query)),
        }, expected)
        path = link.removeprefix(ISSUER_BASE)
        status, _, body = self.request("GET", path)
        self.assertEqual((status, "<form" in body.decode()), (REFERENCE["link/first-page"]["status"], False))
        proceed = re.search(r'href="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        status, _, body = self.request("GET", proceed)
        form = re.search(r'<form id="([^"]+)"[^>]*action="([^"]+)"', body.decode())
        self.assertEqual((status, form.group(1)), (REFERENCE["link/proceed-0"]["status"], REFERENCE["link/proceed-0"]["form"]))
        fields = sorted(set(re.findall(r'<input[^>]*name="([^"]+)"', body.decode())))
        self.assertEqual(fields, REFERENCE["link/proceed-0"]["fields"])
        action = form.group(2).replace("&amp;", "&")
        chosen = secrets.token_urlsafe(30)
        status, _, body = self.request("POST", action, form={"password-new": chosen, "password-confirm": chosen + "x"})
        self.assertEqual(status, 200)
        self.assertIn('id="kc-passwd-update-form"', body.decode())
        status, _, body = self.request("POST", action, form={"password-new": chosen, "password-confirm": chosen})
        self.assertEqual((status, "account has been updated" in body.decode().lower()), (REFERENCE["link/after-update"]["status"], REFERENCE["link/after-update"]["text"]))
        status, _, body = self.request("GET", path)
        self.assertEqual(status, REFERENCE["link/reused"]["status"])
        self.assertEqual(re.findall(r"(expired|already been used|invalid)", body.decode().lower())[:1], REFERENCE["link/reused"]["text"])
        tokens = self.browser_login(self.realm, "mail-app", CALLBACK, "reference-user", chosen)
        self.assertEqual({"signed_in": bool(tokens.get("access_token"))}, REFERENCE["login/new-password"])


if __name__ == "__main__":
    unittest.main()
