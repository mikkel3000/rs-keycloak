"""rememberMe compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/remember-me-observations.json:
the realm settings, the login form's checkbox, the cookies a checked or
unchecked sign-in sets, the refresh token's lifetime and the session
flag, the username and checkbox a remembered browser sees, and the
cookie's removal by an unchecked sign-in. Every recorded case is
replayed; realms are made once per class.
"""

import base64
import json
import pathlib
import sys
import unittest
import urllib.parse

from login_case import LoginCase, reference

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
from remember_me import COOKIES, REALMS, claims  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from login_browser import forms  # noqa: E402

REFERENCE = reference("remember-me-observations.json")


def cookies(browser):
    """As the recorder reduces them."""
    result = {}
    for value in browser.set_cookies:
        name, _, rest = value.partition("=")
        if name not in COOKIES:
            continue
        content, *attributes = [part.strip() for part in rest.split(";")]
        kept = sorted(attribute for attribute in attributes if not attribute.lower().startswith("expires") and attribute)
        result[name] = {"value": content if name == "KEYCLOAK_REMEMBER_ME" else bool(content), "attributes": kept}
    return result


class RememberMeCase(LoginCase):
    REALMS = REALMS

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        for key in REALMS:
            cls.new_user(key, "checked-user")
            cls.new_user(key, "unchecked-user")
        cls.new_user("on", "remember+user")

    def login_form(self, browser, query=None):
        page = browser.authorize(query)
        form = next(form for form in forms(page[2]) if form["id"] == "kc-form-login")
        return self.normalized(browser.shown(page) | {"username_value": form["fields"].get("username"), "checkboxes": form["checkboxes"]})

    def signed_in(self, key, username, checked, browser=None):
        browser = browser or self.browser(key)
        response = browser.sign_in(username, self.password, checked=("rememberMe",) if checked else ())
        result = browser.shown(response) | {"cookies": cookies(browser)}
        tokens = browser.exchange(response)
        refresh = claims(tokens["refresh_token"])
        result["refresh_lifetime"] = refresh["exp"] - refresh["iat"]
        result["refresh_expires_in_matches"] = 0 <= result["refresh_lifetime"] - tokens["refresh_expires_in"] <= 2
        _, user = self.realm_admin(key, "/users?exact=true&username=" + urllib.parse.quote(username))
        _, sessions = self.realm_admin(key, f"/users/{user[0]['id']}/sessions")
        result["session_remember_me"] = sorted(session["rememberMe"] for session in sessions)
        return self.normalized(result), browser


class SettingsContract(RememberMeCase):
    def test_representation_and_login_form(self):
        for key in REALMS:
            _, realm = self.realm_admin(key, "")
            self.assertEqual({field: realm.get(field) for field in ("rememberMe", "ssoSessionIdleTimeoutRememberMe", "ssoSessionMaxLifespanRememberMe", "ssoSessionIdleTimeout", "ssoSessionMaxLifespan")}, REFERENCE[f"representation/{key}"], key)
            self.assertEqual(self.login_form(self.browser(key)), REFERENCE[f"login-form/{key}"], key)


def sign_in(key):
    def test(self):
        for label in ("checked", "unchecked"):
            observed, _ = self.signed_in(key, label + "-user", label == "checked")
            self.assertEqual(observed, REFERENCE[f"sign-in/{key}/{label}"], label)
    return test


class SignInContract(RememberMeCase):
    pass


for name in REALMS:
    setattr(SignInContract, "test_" + name, sign_in(name))


class RememberedBrowserContract(RememberMeCase):
    def test_cookie_fills_the_form_and_is_removed(self):
        observed, remembered = self.signed_in("on", "remember+user", True)
        self.assertEqual(observed, REFERENCE["sign-in/on/encoded-name"])
        cookie = {"KEYCLOAK_REMEMBER_ME": remembered.cookies["KEYCLOAK_REMEMBER_ME"]}
        for key in ("on", "off"):
            browser = self.browser(key)
            browser.cookies = dict(cookie)
            self.assertEqual(self.login_form(browser), REFERENCE[f"prefilled/{key}"], key)
        browser = self.browser("on")
        browser.cookies = dict(cookie)
        self.assertEqual(self.login_form(browser, {"login_hint": "hinted-user"}), REFERENCE["prefilled/on/login-hint"])
        browser = self.browser("on")
        browser.cookies = {"KEYCLOAK_REMEMBER_ME": "name:remember-user"}
        self.assertEqual(self.login_form(browser), REFERENCE["prefilled/on/other-prefix"])
        browser = self.browser("on")
        browser.cookies = dict(cookie)
        observed, _ = self.signed_in("on", "remember+user", False, browser)
        self.assertEqual(observed, REFERENCE["sign-in/on/unchecked-after-remembered"])


if __name__ == "__main__":
    unittest.main()
