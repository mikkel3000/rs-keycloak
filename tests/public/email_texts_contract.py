"""Realm texts in emails compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/email-texts-observations.json:
the forgot-password, execute-actions and verify-email mails of an English
and a German user in a realm with localization texts, a realm without
them, and a realm without internationalization, and a text added later.
The admin API keeps no user attributes here, so the German user sets the
locale through the account API, as tests/public/totp_qr_contract.py does.
Every recorded case is replayed; realms are made once per class.
"""

import json
import pathlib
import re
import sys
import unittest

from fixture import ISSUER_BASE
from login_case import CALLBACK, LoginCase, reference

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
from email_texts import REALMS, summary  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from login_browser import Browser  # noqa: E402
from smtp_sink import SmtpSink  # noqa: E402

REFERENCE = reference("email-texts-observations.json")


class EmailTextsCase(LoginCase):
    @classmethod
    def setUpClass(cls):
        cls.sink = SmtpSink().__enter__()
        smtp = {"host": "127.0.0.1", "port": str(cls.sink.port), "from": "noreply@example.invalid"}
        cls.REALMS = {key: extra | {"resetPasswordAllowed": True, "smtpServer": smtp} for key, extra in REALMS.items()}
        super().setUpClass()
        cls.users = {}
        for key in REALMS:
            cls.users[key, "en"] = cls.new_user(key, "en-user")
            cls.users[key, "de"] = cls.new_user(key, "de-user")
            if key != "no-i18n":
                cls.set_locale(key, "de-user")

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.sink.__exit__(None, None, None)

    @classmethod
    def set_locale(cls, key, username):
        """Signs the user in and stores German as their locale."""
        browser = Browser(cls.call_server, ISSUER_BASE, cls.names[key], CALLBACK)
        tokens = browser.exchange(browser.sign_in(username, cls.password))
        account = {"username": username, "email": username + "@example.invalid", "firstName": "Reference", "lastName": "User", "attributes": {"locale": ["de"]}}
        status, _, _ = cls.request("POST", f"/realms/{cls.names[key]}/account/", {"Authorization": "Bearer " + tokens["access_token"], "Content-Type": "application/json"}, body=json.dumps(account))
        assert status == 204, f"account locale {status}"

    def mailed(self, send):
        before = len(self.sink.received)
        result = send()
        mails = self.sink.wait(before + 1, timeout=5)[before:]
        return self.normalized({"result": result, "mails": [summary(mail) for mail in mails]})

    def forgot(self, key, username):
        browser = self.browser(key)
        page = browser.authorize()
        link = re.search(r'href="([^"]*/login-actions/reset-credentials[^"]*)"', page[2].decode()).group(1)
        form = browser.visit(link)
        return self.shown(browser.submit(form, {"username": username}))["status"]


def mails(key, locale):
    def test(self):
        user, username = self.users[key, locale], locale + "-user"
        self.assertEqual(self.mailed(lambda: self.forgot(key, username)), REFERENCE[f"reset/{key}/{locale}"])
        self.assertEqual(self.mailed(lambda: self.realm_admin(key, f"/users/{user}/execute-actions-email", "PUT", ["UPDATE_PASSWORD"])[0]), REFERENCE[f"execute-actions/{key}/{locale}"])
        self.assertEqual(self.mailed(lambda: self.realm_admin(key, f"/users/{user}/send-verify-email", "PUT")[0]), REFERENCE[f"verify-email/{key}/{locale}"])
    return test


class MailContract(EmailTextsCase):
    pass


for name in REALMS:
    for language in ("en", "de"):
        setattr(MailContract, f"test_{name.replace('-', '_')}_{language}", mails(name, language))


class AddedTextContract(EmailTextsCase):
    def test_text_added_later_is_read_at_sending(self):
        status, _, _ = self.request("PUT", f"/admin/realms/{self.names['plain']}/localization/de/passwordResetSubject", {"Authorization": "Bearer " + self.token, "Content-Type": "text/plain"}, body="Neuer Betreff {0}")
        self.assertEqual({"put": status} | self.mailed(lambda: self.forgot("plain", "de-user")), REFERENCE["reset/plain/de/added-text"])


if __name__ == "__main__":
    unittest.main()
