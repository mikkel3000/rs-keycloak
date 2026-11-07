"""Realm internationalization and the username settings in the login flow,
compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/login-settings-observations.json.
Users and realms are made once per class, so each test is a few exchanges.

Known differences, listed in IMPLEMENTATION.md: the reference sends a
required action through a redirect and sets the KEYCLOAK_LOCALE cookie on
each hop, where this server answers the login post with the page, so the
locale cookies of an exchange are compared as sets.
"""

import hashlib
import html.parser
import json
import pathlib
import re
import secrets
import unittest
import urllib.parse

from fixture import ENDPOINT, ISSUER_BASE, AdminCase, b64


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/login-settings-observations.json").read_text()
)["observations"]
MANY_LOCALES = ["en", "de", "fr", "ar", "pt-BR", "zh-CN", "ja", "fa", "he"]
REALMS = {
    "i18n": {"internationalizationEnabled": True, "supportedLocales": MANY_LOCALES, "defaultLocale": "de"},
    "pair": {"internationalizationEnabled": True, "supportedLocales": ["en", "de"]},
    "off": {"internationalizationEnabled": False, "supportedLocales": ["en", "de"], "defaultLocale": "de"},
    "plain": {},
    "edit": {"editUsernameAllowed": True},
    "email": {"registrationEmailAsUsername": True},
    "both": {"editUsernameAllowed": True, "registrationEmailAsUsername": True},
}
EMAIL_REALMS = ("email", "both")
PROFILE_CASES = {
    "same": {},
    "same-username": None,
    "rename": {"username": "profile-renamed-user"},
    "rename-upper": {"username": "Profile-Renamed-Upper"},
    "taken-username": {"username": "other-user"},
    "blank-username": {"username": ""},
    "new-email": {"email": "profile-changed@example.invalid"},
    "taken-email": {"email": "other@example.invalid"},
    "email-as-other-username": {"email": "other-user"},
}
ADMIN_CASES = {
    "rename": {"username": "admin-renamed-user"},
    "rename-upper": {"username": "Admin-Renamed-Upper"},
    "same-upper": None,
    "taken-username": {"username": "other-user"},
    "blank-username": {"username": ""},
    "null-username": {"username": None},
    "new-email": {"email": "admin-changed@example.invalid"},
    "taken-email": {"email": "other@example.invalid"},
    "email-as-other-username": {"email": "other-user"},
    "username-and-email": {"username": "admin-pair-user", "email": "admin-pair@example.invalid"},
    "clear-email": {"email": ""},
}


class Forms(html.parser.HTMLParser):
    """Collects each form's id, action and input names and values."""

    def __init__(self):
        super().__init__()
        self.forms = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.forms.append({"id": attrs.get("id"), "action": attrs.get("action"), "fields": {}})
        elif tag == "input" and self.forms and attrs.get("name"):
            self.forms[-1]["fields"][attrs["name"]] = attrs.get("value", "")


def first_form(body):
    forms = Forms()
    forms.feed(body.decode())
    return forms.forms[0]


def disabled_names(body):
    return {name for tag in re.findall(r"<input\b[^>]*>", body.decode()) if re.search(r"\sdisabled\b", tag) for name in re.findall(r'\bname="([^"]+)"', tag)}


def errors(body):
    found = re.findall(r'<(\w+)[^>]*\bid="input-error-(?!container-)([a-zA-Z-]+)"[^>]*>(.*?)</\1>', body.decode(), re.S)
    return {name: " ".join(re.sub(r"<[^>]+>", " ", message).split()) for _, name, message in found}


def profile_form(body):
    form = first_form(body)
    return {"form": form["id"], "fields": sorted(form["fields"]), "disabled": sorted(disabled_names(body)), "values": {name: form["fields"][name] for name in ("username", "email") if name in form["fields"]}}


def as_sets(observation):
    """Locale cookies of an exchange, compared as a set."""
    return observation | {"locale_cookie": sorted(set(observation["locale_cookie"]))}


class Browser:
    """One browser on the contract server: a cookie jar, and the Set-Cookie
    headers of its last exchange, including redirects inside login-actions."""

    def __init__(self, case, key, cookies=None):
        self.case, self.key, self.cookies, self.set_cookies = case, key, dict(cookies or {}), []
        self.realm = case.names[key]
        self.redirect = f"{ISSUER_BASE}/realms/{self.realm}/account/"

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

    def authorize(self, headers=None, extra=None):
        self.verifier = secrets.token_urlsafe(48)
        query = urllib.parse.urlencode({"client_id": "account-console", "redirect_uri": self.redirect, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": b64(hashlib.sha256(self.verifier.encode()).digest()), "code_challenge_method": "S256"} | (extra or {}))
        return self.send(f"/realms/{self.realm}/protocol/openid-connect/auth?" + query, headers)

    def submit(self, response, fields, headers=None, query=None):
        form = first_form(response[2])
        action = urllib.parse.urlsplit(urllib.parse.urljoin(ISSUER_BASE, form["action"]))
        target = action.path + ("?" + action.query if action.query else "")
        if query:
            target += ("&" if action.query else "?") + urllib.parse.urlencode(query)
        enabled = {name: value for name, value in form["fields"].items() if name not in disabled_names(response[2])}
        return self.send(target, {"Content-Type": "application/x-www-form-urlencoded"} | (headers or {}), "POST", urllib.parse.urlencode(enabled | fields))

    def token(self, response):
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(response[1]["location"]).query)["code"][0]
        status, _, body = self.case.request("POST", f"/realms/{self.realm}/protocol/openid-connect/token", form={"grant_type": "authorization_code", "client_id": "account-console", "redirect_uri": self.redirect, "code": code, "code_verifier": self.verifier})
        assert status == 200, "code exchange"
        return json.loads(body)["access_token"]


class LoginSettingsCase(AdminCase):
    password = secrets.token_urlsafe(30)
    realm_keys = ()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, _, body = cls.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": cls.ADMIN, "client_secret": cls.ADMIN_SECRET})
        assert status == 200, "admin token"
        cls.token = json.loads(body)["access_token"]
        prefix = "contract-" + secrets.token_hex(5)
        cls.names = {key: f"{prefix}-{key}" for key in cls.realm_keys}
        for key in cls.realm_keys:
            assert cls.admin("POST", "/admin/realms", {"realm": cls.names[key], "enabled": True} | REALMS[key])[0] == 201, key
        cls.users = {}
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
    def new_user(cls, key, case, extra=None, password=True):
        """Creates a user as the recorder did; returns its id and login name."""
        username, email = case + "-user", case + "@example.invalid"
        user = {"username": username, "enabled": True, "firstName": "Reference", "lastName": "User", "email": email, "emailVerified": True} | (extra or {})
        if password:
            user["credentials"] = [{"type": "password", "value": cls.password, "temporary": False}]
        assert cls.admin("POST", f"/admin/realms/{cls.names[key]}/users", user)[0] == 201, (key, case)
        login = email if key in EMAIL_REALMS else username
        _, found = cls.admin("GET", f"/admin/realms/{cls.names[key]}/users?exact=true&username=" + urllib.parse.quote(login))
        return found[0]["id"], login

    @classmethod
    def sign_in(cls, key, login, headers=None, extra=None, query=None, cookies=None):
        browser = Browser(cls, key, cookies)
        page = browser.authorize(headers, extra)
        return browser, browser.submit(page, {"username": login, "password": cls.password}, headers, query)

    @classmethod
    def account(cls, key, token, method="GET", payload=None):
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        status, _, body = cls.request(method, f"/realms/{cls.names[key]}/account/", headers, body=json.dumps(payload) if payload is not None else None)
        return status, json.loads(body) if body else None

    @classmethod
    def user_with_locale(cls, key, case, locale, extra=None):
        user_id, login = cls.new_user(key, case)
        browser, response = cls.sign_in(key, login)
        token = browser.token(response)
        _, own = cls.account(key, token)
        payload = {field: own[field] for field in ("username", "email", "firstName", "lastName")} | {"attributes": {"locale": [locale]}}
        assert cls.account(key, token, "POST", payload)[0] == 204, "locale setup"
        if extra:
            assert cls.admin("PUT", f"/admin/realms/{cls.names[key]}/users/{user_id}", extra)[0] == 204
        return user_id, login

    def clean(self, value):
        text = json.dumps(value)
        for key in sorted(self.names, key=lambda item: -len(self.names[item])):
            text = text.replace(self.names[key], "{realm-" + key + "}")
        return json.loads(text.replace(ISSUER_BASE, "{base}"))

    def shown(self, response, browser):
        status, headers, body = response
        result = {"status": status, "locale_cookie": [value for value in browser.set_cookies if value.startswith("KEYCLOAK_LOCALE=")]}
        if status == 200:
            tag = re.search(r"<html[^>]*>", body.decode()).group(0)
            lang, direction = re.search(r'\blang="([^"]*)"', tag), re.search(r'\bdir="([^"]*)"', tag)
            result |= {"lang": lang and lang.group(1), "dir": direction and direction.group(1)}
        else:
            result["location"] = urllib.parse.urlsplit(headers.get("location", "")).path
        return self.clean(result)

    def assert_shown(self, label, observed):
        self.assertEqual(as_sets(observed), as_sets(REFERENCE[label]), label)

    def admin_user(self, key, user_id):
        _, rep = self.admin("GET", f"/admin/realms/{self.names[key]}/users/{user_id}")
        return [rep["username"], rep.get("email")]


class AuthorizationPages(LoginSettingsCase):
    realm_keys = ("i18n", "pair", "off", "plain")

    def auth_page(self, label, key, headers=None, extra=None, cookies=None):
        browser = Browser(self, key, cookies)
        self.assert_shown(label, self.shown(browser.authorize(headers, extra), browser))

    def test_accept_language(self):
        self.auth_page("auth/i18n/no-header", "i18n")
        for case, accepted in (("accept-fr", "fr"), ("accept-ar", "ar"), ("accept-fa", "fa-IR"), ("accept-he", "he"), ("accept-pt", "pt"), ("accept-unsupported", "it")):
            self.auth_page("auth/i18n/" + case, "i18n", {"Accept-Language": accepted})

    def test_ui_locales_cookie_and_kc_locale(self):
        self.auth_page("auth/i18n/ui-locales", "i18n", {"Accept-Language": "fr"}, {"ui_locales": "it ja"})
        self.auth_page("auth/i18n/ui-locales-unsupported", "i18n", {"Accept-Language": "fr"}, {"ui_locales": "it"})
        self.auth_page("auth/i18n/ui-locales-over-cookie", "i18n", None, {"ui_locales": "ja"}, {"KEYCLOAK_LOCALE": "fr"})
        self.auth_page("auth/i18n/cookie", "i18n", {"Accept-Language": "ja"}, None, {"KEYCLOAK_LOCALE": "fr"})
        self.auth_page("auth/i18n/cookie-unsupported", "i18n", {"Accept-Language": "ja"}, None, {"KEYCLOAK_LOCALE": "it"})
        # kc_locale counts only on login-actions URLs.
        self.auth_page("auth/i18n/kc-locale", "i18n", {"Accept-Language": "fr"}, {"kc_locale": "ar", "ui_locales": "ja"})
        self.auth_page("auth/i18n/kc-locale-unsupported", "i18n", {"Accept-Language": "fr"}, {"kc_locale": "it"})

    def test_other_realms(self):
        self.auth_page("auth/pair/no-header", "pair")
        self.auth_page("auth/pair/accept-fr", "pair", {"Accept-Language": "fr"})
        self.auth_page("auth/pair/accept-de", "pair", {"Accept-Language": "de"})
        self.auth_page("auth/off/accept-de", "off", {"Accept-Language": "de"}, {"kc_locale": "de", "ui_locales": "de"})
        self.auth_page("auth/plain/accept-de", "plain", {"Accept-Language": "de"})


class FailedLogins(LoginSettingsCase):
    realm_keys = ("i18n",)

    @classmethod
    def prepare(cls):
        cls.login = cls.new_user("i18n", "failed")[1]

    def failed(self, label, extra, query):
        browser = Browser(self, "i18n")
        page = browser.authorize(extra=extra)
        browser.cookies.pop("KEYCLOAK_LOCALE", None)
        response = browser.submit(page, {"username": self.login, "password": "wrong"}, None, query)
        self.assert_shown("form/i18n/failed-" + label, self.shown(response, browser))

    def test_ui_locales_stay_with_the_request(self):
        self.failed("ui-locales", {"ui_locales": "ja"}, None)

    def test_kc_locale_on_the_authorization_endpoint(self):
        self.failed("kc-locale", {"kc_locale": "ar"}, None)

    def test_kc_locale_on_the_form(self):
        self.failed("kc-locale-on-form", None, {"kc_locale": "fr"})


class LoginLocale(LoginSettingsCase):
    realm_keys = ("i18n", "off")

    @classmethod
    def prepare(cls):
        for case in ("kc-locale", "kc-locale-form", "kc-locale-unsupported", "no-locale", "ui-locales"):
            cls.users[case] = cls.new_user("i18n", case)[1]
        for case in ("has-locale", "same-locale", "other-locale"):
            cls.users[case] = cls.user_with_locale("i18n", case, "ja")[1]
        cls.users["off"] = cls.new_user("off", "kc-locale")[1]

    def finished(self, label, case, **options):
        browser, response = self.sign_in("i18n", self.users[case], **options)
        _, profile = self.account("i18n", browser.token(response))
        observed = self.shown(response, browser) | {"stored": profile.get("attributes", {}).get("locale")}
        self.assert_shown(label, observed)

    def test_kc_locale_on_the_authorization_endpoint_is_ignored(self):
        self.finished("login/i18n/kc-locale", "kc-locale", extra={"kc_locale": "ar"})

    def test_kc_locale_on_the_form_becomes_the_user_locale(self):
        self.finished("login/i18n/kc-locale-on-form", "kc-locale-form", query={"kc_locale": "fr"})

    def test_unsupported_kc_locale(self):
        self.finished("login/i18n/kc-locale-unsupported", "kc-locale-unsupported", extra={"kc_locale": "it"})

    def test_the_user_locale_is_remembered(self):
        self.finished("login/i18n/user-locale", "has-locale", headers={"Accept-Language": "fr"})

    def test_the_same_kc_locale(self):
        self.finished("login/i18n/kc-locale-same", "same-locale", extra={"kc_locale": "ja"})

    def test_another_kc_locale_on_the_authorization_endpoint(self):
        self.finished("login/i18n/kc-locale-other", "other-locale", extra={"kc_locale": "fr"})

    def test_a_remembered_locale_without_user_locale_is_forgotten(self):
        self.finished("login/i18n/no-locale-cookie", "no-locale", cookies={"KEYCLOAK_LOCALE": "fr"})

    def test_ui_locales_are_not_stored(self):
        self.finished("login/i18n/ui-locales", "ui-locales", extra={"ui_locales": "fr"})

    def test_without_internationalization(self):
        browser, response = self.sign_in("off", self.users["off"], extra={"kc_locale": "de"}, cookies={"KEYCLOAK_LOCALE": "fr"})
        self.assert_shown("login/off/kc-locale", self.shown(response, browser))


class RequiredActionPages(LoginSettingsCase):
    realm_keys = ("i18n", "off")

    @classmethod
    def prepare(cls):
        action = {"requiredActions": ["UPDATE_PROFILE"]}
        cls.users["fa"] = cls.user_with_locale("i18n", "profile-fa", "fa", action)[1]
        cls.users["ja"] = cls.user_with_locale("i18n", "profile-ja", "ja", action)[1]
        cls.users["ui"] = cls.new_user("i18n", "profile-ui", action)[1]
        cls.users["off"] = cls.new_user("off", "profile", action)[1]

    def test_the_user_locale_counts_once_known(self):
        browser, response = self.sign_in("i18n", self.users["fa"], headers={"Accept-Language": "fr"})
        self.assert_shown("action/i18n/user-locale", self.shown(response, browser))

    def test_kc_locale_on_the_authorization_endpoint_is_ignored(self):
        browser, response = self.sign_in("i18n", self.users["ja"], extra={"kc_locale": "ar"})
        self.assert_shown("action/i18n/kc-locale-over-user", self.shown(response, browser))

    def test_ui_locales_and_the_error_page(self):
        browser, response = self.sign_in("i18n", self.users["ui"], extra={"ui_locales": "ja"})
        self.assert_shown("action/i18n/ui-locales", self.shown(response, browser))
        response = browser.submit(response, {"firstName": "", "lastName": "User"}, {"Accept-Language": "fr"})
        self.assert_shown("action/i18n/ui-locales-error", self.shown(response, browser))

    def test_without_internationalization(self):
        browser, response = self.sign_in("off", self.users["off"], headers={"Accept-Language": "de"})
        self.assert_shown("action/off/page", self.shown(response, browser))


class ProfileRules(LoginSettingsCase):
    """UPDATE_PROFILE under each username setting; each case has its own user."""

    realm_keys = ("plain", "edit", "email", "both")

    @classmethod
    def prepare(cls):
        for key in cls.realm_keys:
            cls.admin("POST", f"/admin/realms/{cls.names[key]}/users", {"username": "other-user", "enabled": True, "email": "other@example.invalid"})
            for case in PROFILE_CASES:
                cls.users[key, case] = cls.new_user(key, "profile-" + case, {"requiredActions": ["UPDATE_PROFILE"]})

    def run_case(self, key, case):
        user_id, login = self.users[key, case]
        before = self.admin_user(key, user_id)
        browser, page = self.sign_in(key, login)
        if case == "same":
            self.assertEqual(profile_form(page[2]), REFERENCE[f"profile/{key}/page"], f"{key} page")
        fields = PROFILE_CASES[case]
        if fields is None:
            fields = {"username": before[0]}
        response = browser.submit(page, {"firstName": "Changed", "lastName": "User"} | fields)
        result = {"status": response[0], "errors": errors(response[2]) if response[0] == 200 else {}, "before": before, "after": self.admin_user(key, user_id)}
        if response[0] == 200:
            result["form"] = profile_form(response[2])["values"]
        self.assertEqual(result, REFERENCE[f"profile/{key}/{case}"], f"{key}/{case}")


class AdminRules(LoginSettingsCase):
    """Admin user updates under each username setting; each case has its own user."""

    realm_keys = ("plain", "edit", "email", "both")

    @classmethod
    def prepare(cls):
        for key in cls.realm_keys:
            cls.admin("POST", f"/admin/realms/{cls.names[key]}/users", {"username": "other-user", "enabled": True, "email": "other@example.invalid"})
            for case in ADMIN_CASES:
                cls.users[key, case] = cls.new_user(key, "admin-" + case, password=False)[0]

    def run_realm(self, key):
        for case, payload in ADMIN_CASES.items():
            user_id = self.users[key, case]
            before = self.admin_user(key, user_id)
            if payload is None:
                payload = {"username": before[0].upper()}
            status, body = self.admin("PUT", f"/admin/realms/{self.names[key]}/users/{user_id}", payload)
            observed = {"status": status, "body": body, "before": before, "after": self.admin_user(key, user_id)}
            self.assertEqual(observed, REFERENCE[f"admin/{key}/{case}"], f"{key}/{case}")


def add_tests():
    for key in ProfileRules.realm_keys:
        for case in PROFILE_CASES:
            name = f"test_{key}_{case.replace('-', '_')}"
            setattr(ProfileRules, name, lambda self, key=key, case=case: self.run_case(key, case))
    for key in AdminRules.realm_keys:
        setattr(AdminRules, f"test_{key}", lambda self, key=key: self.run_realm(key))


add_tests()


if __name__ == "__main__":
    unittest.main()
