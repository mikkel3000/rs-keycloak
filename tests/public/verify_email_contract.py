"""Email verification compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/verify-email-observations.json; mail
is received by the in-memory SMTP sink in tests/smtp_sink.py.
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
    (pathlib.Path(__file__).resolve().parents[1] / "reference/verify-email-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


def phrases(html):
    text = html.lower()
    return sorted(p for p in ("already been verified", "been verified", "confirm validity", "click here to proceed", "expired", "invalid") if p in text)


class VerifyEmailContract(AdminCase):
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
        self.assertEqual(self.call("PUT", f"/admin/realms/{self.realm}", {"smtpServer": smtp, "verifyEmail": True})[0], 204)
        self.assertEqual(self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "verify-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        users = f"/admin/realms/{self.realm}/users"
        self.user = self.call("POST", users, {"username": "reference-user", "enabled": True, "email": "reference@example.invalid"})[1]["location"].rsplit("/", 1)[1]
        self.other = self.call("POST", users, {"username": "other-user", "enabled": True, "email": "other@example.invalid"})[1]["location"].rsplit("/", 1)[1]
        self.password = secrets.token_urlsafe(30)
        self.call("PUT", f"{users}/{self.user}/reset-password", {"type": "password", "value": self.password})
        self.users = users
        self.sink.received.clear()

    def link_in(self, received):
        text = received["message"].get_body(preferencelist=("plain",)).get_content()
        return next(url for url in re.findall(r"https?://\S+", text) if "/login-actions/action-token" in url)

    def summarize(self, response):
        status, headers, body = response
        if status in (302, 303):
            return {"status": status, "location_params": sorted(urllib.parse.parse_qs(urllib.parse.urlsplit(headers["location"]).query))}
        return {"status": status, "form": None, "fields": []} if "<form" not in body.decode() else {"status": status, "form": "unexpected"}

    def flags(self, user):
        rep = json.loads(self.call("GET", f"{self.users}/{user}")[2])
        return rep["emailVerified"], rep["requiredActions"]

    def test_login_verification_continues_the_login(self):
        query = urllib.parse.urlencode({"client_id": "verify-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"})
        status, headers, body = self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/auth?{query}")
        cookie = headers["set-cookie"].split(";", 1)[0]
        action = re.search(r'action="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        response = self.request("POST", action, {"Cookie": cookie}, {"username": "reference-user", "password": self.password})
        observed = self.summarize(response)
        observed["resend_link"] = bool(re.search(r'href="[^"]*login-actions/required-action[^"]*"', response[2].decode()))
        self.assertEqual(observed, REFERENCE["login/after-password"])
        received = self.sink.wait(1)
        self.assertEqual({"count": len(received)}, REFERENCE["mail/after-password"])
        message = received[-1]["message"]
        expected = REFERENCE["mail/message"]
        self.assertEqual((received[-1]["to"], str(message["From"]), str(message["Subject"])), (expected["to"], expected["from_header"], expected["subject"]))
        verified, actions = self.flags(self.user)
        self.assertEqual({"emailVerified": verified, "requiredActions": actions}, REFERENCE["admin/user-before-link"])
        path = self.link_in(received[-1]).removeprefix(ISSUER_BASE)
        self.assertEqual(self.summarize(self.request("GET", path, {"Cookie": cookie})), REFERENCE["link/same-browser"])
        verified, actions = self.flags(self.user)
        self.assertEqual({"emailVerified": verified, "requiredActions": actions}, REFERENCE["admin/user-after-link"])
        status, _, body = self.request("GET", path)
        expected = REFERENCE["link/reused"]
        self.assertEqual((status, phrases(body.decode())), (expected["status"], expected["phrases"]))

    def test_admin_sent_link_asks_for_confirmation(self):
        status, _, body = self.call("PUT", f"{self.users}/{self.other}/send-verify-email")
        self.assertEqual({"status": status, "body": json.loads(body) if body else None}, REFERENCE["admin/send-verify-email"])
        received = self.sink.wait(1)[-1]
        self.assertEqual((received["to"], str(received["message"]["Subject"])), (REFERENCE["mail/admin-sent"]["to"], REFERENCE["mail/admin-sent"]["subject"]))
        path = self.link_in(received).removeprefix(ISSUER_BASE)
        status, _, body = self.request("GET", path)
        html = body.decode()
        self.assertEqual(status, REFERENCE["link/admin-sent"]["status"])
        self.assertTrue({"click here to proceed", "confirm validity"} <= set(phrases(html)))
        proceed = re.search(r'href="([^"]*login-actions/action-token[^"]*)"', html).group(1).replace("&amp;", "&")
        status, _, _ = self.request("GET", proceed)
        self.assertEqual(status, REFERENCE["link/admin-proceed"]["status"])
        self.assertEqual({"emailVerified": self.flags(self.other)[0]}, REFERENCE["admin/other-after-link"])
        status, _, body = self.call("PUT", f"{self.users}/00000000-0000-0000-0000-000000000000/send-verify-email")
        self.assertEqual({"status": status, "body": json.loads(body)}, REFERENCE["admin/send-unknown-user"])


if __name__ == "__main__":
    unittest.main()
