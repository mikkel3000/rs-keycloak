"""Info, error and logout pages in each locale, compared with recorded
Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/login-info-page-observations.json;
pages are reduced by tests/page_texts.py, as the recorder reduced them.
Each class makes its realm once, and each case its own user.

Known differences, listed in IMPLEMENTATION.md: language links are
compared by label, selection and locale, not by the step they name, as in
login_messages_contract.py; locale cookies of an exchange are compared as
sets.
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
from otp import Forms  # noqa: E402

REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/login-info-page-observations.json").read_text()
)["observations"]
LOCALES = ["en", "de", "de-CH", "fr", "pt-BR", "zh-CN", "ar", "lv", "eo"]
CALLBACK = ISSUER_BASE + "/callback"
ELSEWHERE = "https://elsewhere.invalid/"


def comparable(observation):
    """An observation without what this server shows differently on purpose."""
    observation = json.loads(json.dumps(observation))
    if "locale_cookie" in observation:
        observation["locale_cookie"] = sorted(set(observation["locale_cookie"]))
    if "languages" in observation:
        observation["languages"]["options"] = [[text, selected, locale] for text, selected, _, locale in observation["languages"]["options"]]
    return observation


class Browser:
    """One browser on the contract server: a cookie jar, a fixed
    Accept-Language, and the Set-Cookie headers of its last exchange,
    including redirects inside login-actions."""

    def __init__(self, case, language=None):
        self.case, self.language, self.cookies, self.set_cookies = case, language, {}, []
        self.verifier = None

    def send(self, path, headers=None, method="GET", body=None):
        self.set_cookies = []
        while True:
            sent = dict(headers or {})
            if self.language:
                sent["Accept-Language"] = self.language
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
            headers = {key: value for key, value in (headers or {}).items() if key != "Content-Type"}

    def visit(self, href):
        parts = urllib.parse.urlsplit(urllib.parse.urljoin(ISSUER_BASE, href.replace("&amp;", "&")))
        return self.send(parts.path + ("?" + parts.query if parts.query else ""))

    def authorize(self, query=None, client="login-app"):
        self.verifier = secrets.token_urlsafe(48)
        params = {"client_id": client, "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": b64(hashlib.sha256(self.verifier.encode()).digest()), "code_challenge_method": "S256"}
        return self.send(f"/realms/{self.case.realm}/protocol/openid-connect/auth?" + urllib.parse.urlencode(params | (query or {})))

    def logout(self, query=None):
        suffix = "?" + urllib.parse.urlencode(query) if query else ""
        return self.send(f"/realms/{self.case.realm}/protocol/openid-connect/logout" + suffix)

    def submit(self, response, fields):
        """Posts the page's first form with the fields added."""
        forms = Forms()
        forms.feed(response[2].decode())
        form = forms.forms[0]
        action = urllib.parse.urlsplit(urllib.parse.urljoin(ISSUER_BASE, form["action"].replace("&amp;", "&")))
        target = action.path + ("?" + action.query if action.query else "")
        return self.send(target, {"Content-Type": "application/x-www-form-urlencoded"}, "POST", urllib.parse.urlencode(form["fields"] | fields))

    def follow(self, response, locale):
        """Follows the page's language link for a locale."""
        links = re.findall(r'<a href="([^"]*)" hreflang="([^"]*)"', response[2].decode())
        return self.visit(next(href for href, tag in links if tag == locale))

    def proceed(self, response):
        """Follows the info page's link onwards."""
        link = re.search(r'<div id="kc-info-message">.*?<a href="([^"]*)"', response[2].decode(), re.S)
        return self.visit(link.group(1))

    def sign_in(self, login, query=None):
        """Signs in and returns the tokens of the code."""
        status, headers, _ = self.submit(self.authorize(query), {"username": login, "password": self.case.password})
        assert status == 302, f"sign-in {status}"
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(headers["location"]).query)["code"][0]
        form = {"grant_type": "authorization_code", "client_id": "login-app", "code": code, "redirect_uri": CALLBACK, "code_verifier": self.verifier}
        status, _, body = self.case.request("POST", f"/realms/{self.case.realm}/protocol/openid-connect/token", form=form)
        assert status == 200, f"token {status}"
        return json.loads(body)


class InfoPagesCase(AdminCase):
    password = secrets.token_urlsafe(30)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, _, body = cls.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": cls.ADMIN, "client_secret": cls.ADMIN_SECRET})
        assert status == 200, "admin token"
        cls.token = json.loads(body)["access_token"]
        cls.sink = SmtpSink().__enter__()
        smtp = {"host": "127.0.0.1", "port": str(cls.sink.port), "from": "noreply@example.invalid"}
        cls.realm = "contract-" + secrets.token_hex(5) + "-info"
        settings = {"realm": cls.realm, "enabled": True, "displayName": "Localized Realm", "internationalizationEnabled": True, "supportedLocales": LOCALES, "defaultLocale": "fr"}
        assert cls.admin("POST", "/admin/realms", settings)[0] == 201, "realm"
        assert cls.admin("PUT", f"/admin/realms/{cls.realm}", {"smtpServer": smtp})[0] == 204, "smtp"
        for client in (
            {"clientId": "login-app", "publicClient": True, "redirectUris": [CALLBACK], "attributes": {"post.logout.redirect.uris": CALLBACK + "/logged-out"}},
            {"clientId": "bearer-app", "bearerOnly": True},
        ):
            assert cls.admin("POST", f"/admin/realms/{cls.realm}/clients", client)[0] == 201, client["clientId"]

    def setUp(self):
        """The class's realm replaces the per-test realm."""

    def tearDown(self):
        """The class's realm is removed with the class."""

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "realm"):
            cls.admin("DELETE", "/admin/realms/" + cls.realm)
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
    def new_user(cls, case, extra=None, locale=None):
        """Makes a user; a locale is set through the account API, as this
        server's admin API keeps no user attributes."""
        username = case + "-user"
        user = {"username": username, "enabled": True, "firstName": "Reference", "lastName": "User", "email": case + "@example.invalid", "emailVerified": True, "credentials": [{"type": "password", "value": cls.password, "temporary": False}]}
        assert cls.admin("POST", f"/admin/realms/{cls.realm}/users", user)[0] == 201, case
        _, found = cls.admin("GET", f"/admin/realms/{cls.realm}/users?exact=true&username={username}")
        user_id = found[0]["id"]
        if locale:
            token = Browser(cls).sign_in(username)["access_token"]
            headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
            payload = {field: user[field] for field in ("username", "email", "firstName", "lastName")} | {"attributes": {"locale": [locale]}}
            status, _, _ = cls.request("POST", f"/realms/{cls.realm}/account/", headers, body=json.dumps(payload))
            assert status == 204, f"locale for {case}: {status}"
        if extra:
            assert cls.admin("PUT", f"/admin/realms/{cls.realm}/users/{user_id}", extra)[0] == 204, case
        return username, user_id

    def emailed(self, path, payload=None):
        """Sends an admin email and returns its action link."""
        status, _ = self.admin("PUT", f"/admin/realms/{self.realm}" + path, payload)
        self.assertEqual(status, 204, path)
        _, link = mail_summary(self.sink.wait(1)[-1], ISSUER_BASE, self.realm)
        return link

    def shown(self, response, browser):
        status, headers, body = response
        result = {"status": status, "locale_cookie": sorted(set(value for value in browser.set_cookies if value.startswith("KEYCLOAK_LOCALE=")))}
        if status in (302, 303):
            result["location"] = urllib.parse.urlsplit(headers.get("location", "")).path.replace(ISSUER_BASE, "")
        else:
            tag = re.search(r"<html[^>]*>", body.decode()).group(0)
            lang, direction = re.search(r'\blang="([^"]*)"', tag), re.search(r'\bdir="([^"]*)"', tag)
            texts = page_texts(body)
            result |= {"lang": lang and lang.group(1), "dir": direction and direction.group(1)} | {key: value for key, value in texts.items() if value not in (None, [], {})}
        return json.loads(json.dumps(result).replace(self.realm, "{realm}"))

    def check(self, label, response, browser):
        self.assertEqual(comparable(self.shown(response, browser)), comparable(REFERENCE[label]), label)


class ActionPagesContract(InfoPagesCase):
    def test_action_list_in_each_locale_source(self):
        _, plain = self.new_user("actions")
        link = self.emailed(f"/users/{plain}/execute-actions-email", ["UPDATE_PASSWORD"])
        browser = Browser(self)
        self.check("actions/default", browser.visit(link), browser)
        german = Browser(self, "de")
        self.check("actions/accept-de", german.visit(link), german)

    def test_action_list_in_the_user_locale(self):
        _, arabic = self.new_user("actions-ar", locale="ar")
        other = Browser(self, "de")
        self.check("actions/user-ar", other.visit(self.emailed(f"/users/{arabic}/execute-actions-email", ["UPDATE_PASSWORD"])), other)

    def test_switch_proceed_and_reuse(self):
        _, user = self.new_user("actions-switch")
        link = self.emailed(f"/users/{user}/execute-actions-email", ["UPDATE_PASSWORD"])
        browser = Browser(self)
        switched = browser.follow(browser.visit(link), "de")
        self.check("switch/actions/to-de", switched, browser)
        form = browser.proceed(switched)
        self.check("actions-proceed/de", form, browser)
        self.check("actions-updated/de", browser.submit(form, {"password-new": self.password + "x", "password-confirm": self.password + "x"}), browser)
        self.check("actions-reused/de", browser.visit(link), browser)
        fresh = Browser(self, "ar")
        self.check("actions-reused/accept-ar", fresh.visit(link), fresh)

    def test_unknown_key(self):
        browser = Browser(self, "de")
        self.check("actions-invalid/accept-de", browser.send(f"/realms/{self.realm}/login-actions/action-token?key=" + "x" * 64), browser)


class VerifyPagesContract(InfoPagesCase):
    def test_confirm_switch_verify_and_reuse(self):
        _, user = self.new_user("verify", {"emailVerified": False})
        link = self.emailed(f"/users/{user}/send-verify-email")
        browser = Browser(self, "de")
        confirm = browser.visit(link)
        self.check("verify-confirm/accept-de", confirm, browser)
        switched = browser.follow(confirm, "ar")
        self.check("switch/verify-confirm/to-ar", switched, browser)
        self.check("verify-done/ar", browser.proceed(switched), browser)
        self.check("verify-reused/ar", browser.visit(link), browser)
        fresh = Browser(self, "de")
        self.check("verify-reused/accept-de", fresh.visit(link), fresh)


class LogoutPagesContract(InfoPagesCase):
    def test_confirm_without_session(self):
        browser = Browser(self, "de")
        confirm = browser.logout()
        self.check("logout-confirm/accept-de", confirm, browser)
        other = Browser(self, "de")
        self.check("logout-confirm/ui-ar", other.logout({"ui_locales": "ar"}), other)
        switched = browser.follow(confirm, "fr")
        self.check("switch/logout-confirm/to-fr", switched, browser)
        done = browser.submit(switched, {})
        self.check("logged-out/fr", done, browser)
        self.check("switch/logged-out/to-de", browser.follow(done, "de"), browser)

    def test_confirm_with_session(self):
        login, _ = self.new_user("logout-de", locale="de")
        browser = Browser(self, "ar")
        browser.sign_in(login)
        confirm = browser.logout()
        self.check("logout-confirm/session-de", confirm, browser)
        self.check("logged-out/session-de", browser.submit(confirm, {}), browser)
        page = browser.authorize()
        self.assertEqual({"status": page[0], "form": bool(re.search(r'name="password"', page[2].decode()))}, REFERENCE["after-logout/login"])

    def test_hint_logs_out_without_confirmation(self):
        login, _ = self.new_user("logout-hint", locale="ar")
        browser = Browser(self, "de")
        tokens = browser.sign_in(login)
        self.check("logged-out/hint-ar", browser.logout({"id_token_hint": tokens["id_token"]}), browser)

    def test_refused_logouts(self):
        for label, query in (
            ("logout-error/invalid-hint/accept-de", {"id_token_hint": "not-a-token"}),
            ("logout-error/redirect/accept-de", {"client_id": "login-app", "post_logout_redirect_uri": ELSEWHERE}),
            ("logout-error/redirect/ui-ar", {"client_id": "login-app", "post_logout_redirect_uri": ELSEWHERE, "ui_locales": "ar"}),
        ):
            browser = Browser(self, "de")
            self.check(label, browser.logout(query), browser)


class TotpSetupKeyContract(InfoPagesCase):
    def test_setup_keeps_its_key_until_a_new_authorization(self):
        login, _ = self.new_user("totp", {"requiredActions": ["CONFIGURE_TOTP"]})
        browser = Browser(self)
        fields = {"username": login, "password": self.password}
        page = browser.submit(browser.authorize({"ui_locales": "de"}), fields)

        def key(response):
            forms = Forms()
            forms.feed(response[2].decode())
            return next(form for form in forms.forms if "totpSecret" in form["fields"])["fields"]["totpSecret"]

        first = key(page)
        switched = browser.follow(page, "fr")
        wrong = browser.submit(switched, {"totp": "", "userLabel": ""})
        again = browser.submit(browser.authorize({"ui_locales": "de"}), fields)
        observed = {"after_switch": key(switched) == first, "after_error": key(wrong) == first, "after_new_authorization": key(again) == first}
        self.assertEqual(observed, REFERENCE["configure-totp/key"])


class AuthorizeErrorContract(InfoPagesCase):
    def test_refused_authorizations(self):
        for label, query, client in (
            ("authorize-error/unknown-client/accept-de", None, "missing-app"),
            ("authorize-error/redirect/accept-de", {"redirect_uri": ELSEWHERE}, "login-app"),
            ("authorize-error/redirect/ui-ar", {"redirect_uri": ELSEWHERE, "ui_locales": "ar"}, "login-app"),
            ("authorize-error/bearer-only/accept-de", None, "bearer-app"),
        ):
            browser = Browser(self, "de")
            self.check(label, browser.authorize(query, client), browser)
        browser = Browser(self, "de")
        browser.cookies["KEYCLOAK_LOCALE"] = "ar"
        self.check("authorize-error/redirect/cookie-ar", browser.authorize({"redirect_uri": ELSEWHERE}), browser)

    def test_detached_language_link(self):
        """An error page's language link re-shows its message in this
        browser only, as the reference's state cookie allows."""
        browser = Browser(self, "de")
        switched = browser.follow(browser.authorize({"redirect_uri": ELSEWHERE}), "ar")
        expected = comparable(REFERENCE["authorize-error/redirect/cookie-ar"])
        shown = comparable(self.shown(switched, browser))
        self.assertEqual(len(shown.pop("locale_cookie")), 1)
        expected.pop("locale_cookie")
        self.assertEqual(shown, expected)
        href = re.findall(r'<a href="([^"]*)" hreflang="de"', switched[2].decode())[0]
        stranger = Browser(self, "de")
        other = self.shown(stranger.visit(href), stranger)
        self.assertEqual(other["status"], 400)
        self.assertNotEqual(other["instructions"], REFERENCE["authorize-error/redirect/accept-de"]["instructions"])


if __name__ == "__main__":
    unittest.main()
