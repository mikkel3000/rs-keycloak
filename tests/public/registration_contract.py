"""Registration compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/registration-observations.json:
the login page's link, the registration form and its fields, each
validation failure with the values kept and no user made, passing
registrations with the users they make and signing in with the new
password, registrationEmailAsUsername, the back-to-login link, and the
error page of a realm without registration, reached here at this
server's registration URL. Every recorded case is replayed; realms are
made once per class.
"""

import pathlib
import re
import sys
import unittest
import urllib.parse

from login_case import LoginCase, reference

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
from registration import FIELDS, REALMS  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from login_browser import forms  # noqa: E402

REFERENCE = reference("registration-observations.json")


def register_link(page):
    found = re.search(r'href="([^"]*/login-actions/registration[^"]*)"', page[2].decode())
    return found.group(1) if found else None


class RegistrationCase(LoginCase):
    REALMS = REALMS

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.new_user("open", "taken-user", {"email": "taken@example.invalid"})

    def valid(self):
        return {"username": "new-user", "email": "new-user@example.invalid", "firstName": "Given", "lastName": "Family", "password": self.password, "password-confirm": self.password}

    def post(self, key, values):
        browser = self.browser(key)
        page = browser.visit(register_link(browser.authorize()))
        return browser, browser.submit(page, values, form_id="kc-register-form")

    def user(self, key, username):
        _, found = self.realm_admin(key, "/users?exact=true&username=" + urllib.parse.quote(username))
        return [{field: entry.get(field) for field in ("username", "email", "firstName", "lastName", "enabled", "emailVerified", "requiredActions")} for entry in found]


class FormContract(RegistrationCase):
    def test_link_form_and_back(self):
        for key in REALMS:
            _, realm = self.realm_admin(key, "")
            self.assertEqual({"registrationAllowed": realm.get("registrationAllowed")}, REFERENCE[f"representation/{key}"])
            browser = self.browser(key)
            page = browser.authorize()
            link = register_link(page)
            self.assertEqual(self.shown(page) | {"register_link": bool(link)}, REFERENCE[f"login-form/{key}"], key)
            if not link:
                continue
            registration = browser.visit(link)
            fields = next(found for found in forms(registration[2]) if found["id"] == "kc-register-form")["fields"]
            self.assertEqual(self.shown(registration) | {"fields": [name for name in fields if name in FIELDS]}, REFERENCE[f"form/{key}"], key)
            back = re.search(r'<a[^>]*href="([^"]*)"[^>]*>[^<]*Back to Login', registration[2].decode())
            self.assertEqual(self.shown(browser.visit(back.group(1))), REFERENCE[f"back-to-login/{key}"], key)

    def test_realm_without_registration(self):
        browser = self.browser("closed")
        page = browser.authorize()
        action = re.search(r'action="([^"]*)"', page[2].decode()).group(1).replace("&amp;", "&")
        request_id = urllib.parse.urlsplit(action).path.rsplit("/", 1)[1]
        target = f"/realms/{self.names['closed']}/login-actions/registration/{request_id}"
        self.assertEqual(self.shown(browser.send(target)), REFERENCE["closed/registration-url"])


def failing(label):
    def test(self):
        valid = self.valid()
        values = {
            "empty": {name: "" for name in FIELDS},
            "short-username": valid | {"username": "ab"},
            "bad-username": valid | {"username": "bad name<"},
            "bad-email": valid | {"email": "not-an-email"},
            "bad-names": valid | {"firstName": "Given<", "lastName": "x" * 256},
            "taken-username": valid | {"username": "Taken-User"},
            "taken-email": valid | {"email": "TAKEN@example.invalid"},
            "taken-both": valid | {"username": "taken-user", "email": "taken@example.invalid"},
            "no-password": valid | {"password": "", "password-confirm": ""},
            "mismatch": valid | {"password-confirm": self.password + "x"},
            "mismatch-and-bad-email": valid | {"email": "nope", "password-confirm": "other"},
        }[label]
        _, response = self.post("open", values)
        kept = {name: value for name, value in forms(response[2])[0]["fields"].items() if name in FIELDS} if response[0] == 200 else None
        self.assertEqual(self.shown(response) | {"kept": kept}, REFERENCE[f"failing/{label}"])
        created = self.user("open", values["username"].lower()) if values["username"] else []
        self.assertEqual(created, REFERENCE[f"failing/{label}/created"])
    return test


class FailingContract(RegistrationCase):
    pass


for name in ("empty", "short-username", "bad-username", "bad-email", "bad-names", "taken-username", "taken-email", "taken-both", "no-password", "mismatch", "mismatch-and-bad-email"):
    setattr(FailingContract, "test_" + name.replace("-", "_"), failing(name))


class PassingContract(RegistrationCase):
    def test_open_realm(self):
        _, response = self.post("open", self.valid())
        self.assertEqual(self.shown(response), REFERENCE["passing/open"])
        self.assertEqual(self.user("open", "new-user"), REFERENCE["passing/open/user"])
        self.assertEqual(self.shown(self.browser("open").sign_in("new-user", self.password)), REFERENCE["passing/open/sign-in"])

    def test_mixed_case(self):
        _, response = self.post("open", self.valid() | {"username": "Mixed.Case", "email": "Mixed.Case@Example.Invalid"})
        self.assertEqual(self.shown(response), REFERENCE["passing/open/mixed-case"])
        self.assertEqual(self.user("open", "mixed.case"), REFERENCE["passing/open/mixed-case/user"])

    def test_email_as_username(self):
        values = {name: value for name, value in self.valid().items() if name != "username"} | {"email": "Email.User@example.invalid"}
        _, response = self.post("email", values)
        self.assertEqual(self.shown(response), REFERENCE["passing/email"])
        self.assertEqual(self.user("email", "email.user@example.invalid"), REFERENCE["passing/email/user"])
        _, response = self.post("email", values)
        self.assertEqual(self.shown(response), REFERENCE["failing/email/taken"])
        _, response = self.post("email", values | {"email": ""})
        self.assertEqual(self.shown(response), REFERENCE["failing/email/empty"])


if __name__ == "__main__":
    unittest.main()
