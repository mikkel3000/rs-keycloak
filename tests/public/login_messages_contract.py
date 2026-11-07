"""Login page texts in each locale, compared with recorded Keycloak 26.8.1
behavior.

Expected cases come from tests/reference/login-message-observations.json;
pages are reduced by tests/page_texts.py, as the recorder reduced them.
Realms and users are made once per class, so each test is a few exchanges.

Known differences, listed in IMPLEMENTATION.md: language links are
compared by label, selection and locale, not by the login-actions step
they name, since this server re-shows every step through
login-actions/authenticate; a page in a locale outside the theme whose
language the theme lacks (eo) labels languages from its fallback locale,
where the reference asks the JDK, so only selection and locales are
compared there; the TOTP setup page shows the manual-entry steps without a
QR code, so its list items and links are not compared; locale cookies of
an exchange are compared as sets, since the reference sets them on each
redirect hop.
"""

import hashlib
import json
import pathlib
import re
import secrets
import sys
import unittest
import urllib.parse

from fixture import ENDPOINT, ISSUER_BASE, AdminCase, b64

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from page_texts import page_texts  # noqa: E402
from smtp_sink import SmtpSink  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
from execute_actions import mail_summary  # noqa: E402
from otp import Forms, totp  # noqa: E402

REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/login-message-observations.json").read_text()
)["observations"]
LOCALES = ["en", "de", "de-CH", "fr", "pt-BR", "zh-CN", "ar", "lv", "eo"]
I18N = {"internationalizationEnabled": True, "supportedLocales": LOCALES, "defaultLocale": "fr"}
REALMS = {
    "i18n": I18N | {"resetPasswordAllowed": True},
    "nodefault": {"internationalizationEnabled": True, "supportedLocales": ["en", "de", "de-CH"]},
    "off": {"internationalizationEnabled": False, "supportedLocales": ["en", "de"], "defaultLocale": "de", "resetPasswordAllowed": True},
    "single": {"internationalizationEnabled": True, "supportedLocales": ["de"], "defaultLocale": "de"},
    "verify": I18N | {"verifyEmail": True},
}
CALLBACK = ISSUER_BASE + "/callback"
# Pages whose locale the theme lacks, with no table for its language.
JDK_LABELS = {"login/i18n/eo", "login-failed/i18n/eo", "update-password/i18n/eo"}


def comparable(label, observation):
    """An observation without what this server shows differently on purpose."""
    observation = json.loads(json.dumps(observation)) | {"locale_cookie": sorted(set(observation["locale_cookie"]))}
    if "languages" in observation:
        options = [[text, selected, locale] for text, selected, _, locale in observation["languages"]["options"]]
        if label in JDK_LABELS:
            options = sorted([None, selected, locale] for _, selected, locale in options)
        observation["languages"]["options"] = options
    if "configure-totp" in label:
        observation.pop("items", None)
        observation.pop("links", None)
    return observation


class Browser:
    """One browser on the contract server: a cookie jar, and the Set-Cookie
    headers of its last exchange, including redirects inside login-actions."""

    def __init__(self, case, key):
        self.case, self.key, self.cookies, self.set_cookies = case, key, {}, []
        self.realm = case.names[key]

    def send(self, path, headers=None, method="GET", body=None):
        self.set_cookies = []
        while True:
            sent = dict(headers or {})
            if self.cookies:
                sent["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            status, pairs, data = self.case.request_all(method, path, sent, body=body)
            hop = [value for name, value in pairs if name.lower() == "set-cookie"]
            self.set_cookies += hop
            for value in hop:
                name, _, rest = value.partition("=")
                content = rest.split(";", 1)[0]
                if content and "max-age=0" not in value.lower():
                    self.cookies[name] = content
                else:
                    self.cookies.pop(name, None)
            found = {k.lower(): v for k, v in pairs}
            target = urllib.parse.urlsplit(found.get("location", ""))
            if status not in (302, 303) or "/login-actions/" not in target.path:
                return status, found, data
            path, method, body = target.path + ("?" + target.query if target.query else ""), "GET", None

    def authorize(self, locale=None, client="login-app"):
        verifier = secrets.token_urlsafe(48)
        extra = {"ui_locales": locale} if locale else {}
        query = urllib.parse.urlencode({"client_id": client, "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": b64(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"} | extra)
        return self.send(f"/realms/{self.realm}/protocol/openid-connect/auth?" + query)

    def submit(self, response, fields):
        forms = Forms()
        forms.feed(response[2].decode())
        form = forms.forms[0]
        action = urllib.parse.urlsplit(urllib.parse.urljoin(ISSUER_BASE, form["action"]))
        target = action.path + ("?" + action.query if action.query else "")
        return self.send(target, {"Content-Type": "application/x-www-form-urlencoded"}, "POST", urllib.parse.urlencode(form["fields"] | fields))

    def visit(self, href):
        parts = urllib.parse.urlsplit(urllib.parse.urljoin(ISSUER_BASE, href))
        return self.send(parts.path + ("?" + parts.query if parts.query else ""))

    def follow(self, response, locale):
        """Follows the page's language link for a locale."""
        links = re.findall(r'<a href="([^"]*)" hreflang="([^"]*)"', response[2].decode())
        href = next(href for href, tag in links if tag == locale)
        return self.visit(href.replace("&amp;", "&"))

    def forgot(self, response):
        """Follows the login page's forgot-password link."""
        href = re.search(r'href="([^"]*/login-actions/reset-credentials[^"]*)"', response[2].decode()).group(1)
        return self.visit(href.replace("&amp;", "&"))


class LoginMessagesCase(AdminCase):
    password = secrets.token_urlsafe(30)
    realm_keys = ()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, _, body = cls.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": cls.ADMIN, "client_secret": cls.ADMIN_SECRET})
        assert status == 200, "admin token"
        cls.token = json.loads(body)["access_token"]
        cls.sink = SmtpSink().__enter__()
        smtp = {"host": "127.0.0.1", "port": str(cls.sink.port), "from": "noreply@example.invalid"}
        prefix = "contract-" + secrets.token_hex(5)
        cls.names = {key: f"{prefix}-{key}" for key in cls.realm_keys}
        for key in cls.realm_keys:
            name = cls.names[key]
            assert cls.admin("POST", "/admin/realms", {"realm": name, "enabled": True, "displayName": "Localized Realm"} | REALMS[key])[0] == 201, key
            assert cls.admin("PUT", f"/admin/realms/{name}", {"smtpServer": smtp})[0] == 204, key
            for client in ({"clientId": "login-app", "publicClient": True, "redirectUris": [CALLBACK]}, {"clientId": "consent-app", "publicClient": True, "consentRequired": True, "redirectUris": [CALLBACK]}):
                assert cls.admin("POST", f"/admin/realms/{name}/clients", client)[0] == 201, key
        cls.prepare()

    @classmethod
    def prepare(cls):
        """Subclasses make their users here."""

    def setUp(self):
        """The class's realms replace the per-test realm."""

    def tearDown(self):
        """The class's realms are removed with the class."""

    @classmethod
    def tearDownClass(cls):
        for name in getattr(cls, "names", {}).values():
            cls.admin("DELETE", "/admin/realms/" + name)
        if hasattr(cls, "sink"):
            cls.sink.__exit__(None, None, None)
        super().tearDownClass()

    @classmethod
    def admin(cls, method, path, payload=None):
        headers = {"Authorization": "Bearer " + cls.token}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload)
        status, _, data = cls.request(method, path, headers, body=body)
        return status, json.loads(data) if data else None

    @classmethod
    def new_user(cls, key, case, extra=None):
        username = case + "-user"
        user = {"username": username, "enabled": True, "firstName": "Reference", "lastName": "User", "email": case + "@example.invalid", "emailVerified": True, "credentials": [{"type": "password", "value": cls.password, "temporary": False}]} | (extra or {})
        assert cls.admin("POST", f"/admin/realms/{cls.names[key]}/users", user)[0] == 201, (key, case)
        return username

    @classmethod
    def sign_in(cls, key, case, locale, extra=None, client="login-app"):
        login = cls.new_user(key, case, extra)
        browser = Browser(cls, key)
        page = browser.authorize(locale, client)
        return browser, browser.submit(page, {"username": login, "password": cls.password})

    def shown(self, response, browser):
        status, headers, body = response
        result = {"status": status, "locale_cookie": [value for value in browser.set_cookies if value.startswith("KEYCLOAK_LOCALE=")]}
        if status != 200:
            result["location"] = urllib.parse.urlsplit(headers.get("location", "")).path
        else:
            tag = re.search(r"<html[^>]*>", body.decode()).group(0)
            lang, direction = re.search(r'\blang="([^"]*)"', tag), re.search(r'\bdir="([^"]*)"', tag)
            texts = page_texts(body)
            texts["items"].sort()
            result |= {"lang": lang and lang.group(1), "dir": direction and direction.group(1)} | {key: value for key, value in texts.items() if value not in (None, [], {})}
        text = json.dumps(result)
        for key in sorted(self.names, key=lambda item: -len(self.names[item])):
            text = text.replace(self.names[key], "{realm-" + key + "}")
        return json.loads(text)

    def check(self, label, response, browser):
        self.assertEqual(comparable(label, self.shown(response, browser)), comparable(label, REFERENCE[label]), label)


class LoginPageContract(LoginMessagesCase):
    realm_keys = ("i18n", "nodefault", "off", "single")

    def login_case(self, key, locale, failed):
        browser = Browser(self, key)
        page = browser.authorize(locale)
        self.check(f"login/{key}/{locale or 'none'}", page, browser)
        if failed:
            response = browser.submit(page, {"username": "nobody", "password": "wrong"})
            self.check(f"login-failed/{key}/{locale}", response, browser)

    def test_english(self):
        self.login_case("i18n", "en", False)

    def test_german(self):
        self.login_case("i18n", "de", True)

    def test_swiss_german_falls_back_to_german(self):
        self.login_case("i18n", "de-CH", True)

    def test_french_default(self):
        self.login_case("i18n", "fr", False)

    def test_brazilian_portuguese(self):
        self.login_case("i18n", "pt-BR", False)

    def test_simplified_chinese(self):
        self.login_case("i18n", "zh-CN", False)

    def test_arabic_right_to_left(self):
        self.login_case("i18n", "ar", True)

    def test_latvian_falls_back_to_the_default(self):
        self.login_case("i18n", "lv", True)

    def test_locale_without_bundles(self):
        self.login_case("i18n", "eo", True)

    def test_without_default_locale(self):
        self.login_case("nodefault", "de-CH", True)
        self.login_case("nodefault", None, False)

    def test_internationalization_off(self):
        self.login_case("off", "de", False)

    def test_single_locale_offers_no_choice(self):
        self.login_case("single", None, False)

    def test_language_link_reshows_the_login(self):
        browser = Browser(self, "i18n")
        switched = browser.follow(browser.authorize("de"), "ar")
        self.check("switch/login/to-ar", switched, browser)
        response = browser.submit(switched, {"username": "nobody", "password": "wrong"})
        self.check("switch/login/failed-after", response, browser)


class ResetPageContract(LoginMessagesCase):
    realm_keys = ("i18n", "off")

    def test_reset_pages(self):
        for locale in ("de", "ar", "lv"):
            browser = Browser(self, "i18n")
            reset = browser.forgot(browser.authorize(locale))
            self.check(f"reset/i18n/{locale}", reset, browser)
        browser = Browser(self, "off")
        self.check("reset/off/de", browser.forgot(browser.authorize("de")), browser)

    def test_empty_username_and_language_link(self):
        browser = Browser(self, "i18n")
        reset = browser.forgot(browser.authorize("de"))
        self.check("reset-empty/i18n/de", browser.submit(reset, {"username": ""}), browser)
        switched = browser.follow(reset, "fr")
        self.check("switch/reset/to-fr", switched, browser)
        login = self.new_user("i18n", "reset-de")
        self.check("reset-sent/i18n/fr", browser.submit(switched, {"username": login}), browser)
        _, link = mail_summary(self.sink.wait(1)[-1], ISSUER_BASE, self.names["i18n"])
        page = browser.visit(link)
        self.check("reset-link/i18n/de", page, browser)
        response = browser.submit(page, {"password-new": "one", "password-confirm": "two"})
        self.check("reset-link-mismatch/i18n/de", response, browser)
        self.check("switch/reset-link/to-fr", browser.follow(response, "fr"), browser)


class RequiredActionContract(LoginMessagesCase):
    realm_keys = ("i18n", "verify")

    @classmethod
    def prepare(cls):
        # A user whose authenticator was set up after picking fr, as the
        # recorder's setup chain leaves it.
        browser, page = cls.sign_in("i18n", "totp-de", "de", {"requiredActions": ["CONFIGURE_TOTP"]})
        switched = browser.follow(page, "fr")
        # The re-shown page has a new key, unlike the reference's.
        forms = Forms()
        forms.feed(switched[2].decode())
        cls.otp_secret = forms.forms[0]["fields"]["totpSecret"]
        done = browser.submit(switched, {"totp": totp(cls.otp_secret), "userLabel": ""})
        assert done[0] == 302, "authenticator setup"

    def test_update_password(self):
        for locale in ("de", "ar", "eo"):
            browser, page = self.sign_in("i18n", f"password-{locale}", locale, {"requiredActions": ["UPDATE_PASSWORD"]})
            self.check(f"update-password/i18n/{locale}", page, browser)
            if locale == "de":
                response = browser.submit(page, {"password-new": "one", "password-confirm": "two"})
                self.check("update-password-mismatch/i18n/de", response, browser)
                response = browser.submit(response, {"password-new": "", "password-confirm": ""})
                self.check("update-password-empty/i18n/de", response, browser)
                self.check("switch/update-password/to-pt-BR", browser.follow(response, "pt-BR"), browser)

    def test_update_profile(self):
        for locale in ("de", "zh-CN"):
            browser, page = self.sign_in("i18n", f"profile-{locale}", locale, {"requiredActions": ["UPDATE_PROFILE"]})
            self.check(f"update-profile/i18n/{locale}", page, browser)
            response = browser.submit(page, {"firstName": "", "lastName": "", "email": ""})
            self.check(f"update-profile-empty/i18n/{locale}", response, browser)
            if locale == "de":
                response = browser.submit(response, {"firstName": "Changed", "lastName": "User", "email": "not-an-email"})
                self.check("update-profile-invalid-email/i18n/de", response, browser)
                self.check("switch/update-profile/to-ar", browser.follow(response, "ar"), browser)

    def test_configure_totp(self):
        for locale in ("de", "pt-BR"):
            browser, page = self.sign_in("i18n", f"totp-setup-{locale}", locale, {"requiredActions": ["CONFIGURE_TOTP"]})
            self.check(f"configure-totp/i18n/{locale}", page, browser)
            forms = Forms()
            forms.feed(page[2].decode())
            wrong = "000000" if totp(forms.forms[0]["fields"]["totpSecret"]) != "000000" else "111111"
            response = browser.submit(page, {"totp": wrong, "userLabel": ""})
            self.check(f"configure-totp-wrong/i18n/{locale}", response, browser)
            response = browser.submit(response, {"totp": "", "userLabel": ""})
            self.check(f"configure-totp-empty/i18n/{locale}", response, browser)
            if locale == "de":
                self.check("switch/configure-totp/to-fr", browser.follow(response, "fr"), browser)

    def test_otp_code(self):
        browser = Browser(self, "i18n")
        page = browser.submit(browser.authorize("de"), {"username": "totp-de-user", "password": self.password})
        self.check("otp/i18n/de", page, browser)
        wrong = "000000" if totp(self.otp_secret) != "000000" else "111111"
        response = browser.submit(page, {"otp": wrong})
        self.check("otp-wrong/i18n/de", response, browser)
        self.check("switch/otp/to-ar", browser.follow(response, "ar"), browser)

    def test_verify_email(self):
        for locale in ("de", "lv"):
            browser, page = self.sign_in("verify", f"verify-{locale}", locale, {"emailVerified": False})
            self.check(f"verify-email/verify/{locale}", page, browser)
            if locale == "de":
                self.check("switch/verify-email/to-fr", browser.follow(page, "fr"), browser)


class ConsentPageContract(LoginMessagesCase):
    realm_keys = ("i18n",)

    def test_consent(self):
        for locale in ("de", "ar", "de-CH"):
            browser, page = self.sign_in("i18n", f"consent-{locale}", locale, client="consent-app")
            self.check(f"consent/i18n/{locale}", page, browser)
            if locale == "de":
                self.check("switch/consent/to-fr", browser.follow(page, "fr"), browser)


if __name__ == "__main__":
    unittest.main()
