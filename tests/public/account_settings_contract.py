"""Realm and client settings in the account console, compared with recorded
Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/account-settings-observations.json.
The page cases need RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR naming a directory filled
by compatibility/extract_account_console.py, and fail without it.

Known differences, listed in IMPLEMENTATION.md: supported locales are listed
sorted, where the reference lists them in its hash set's order, so they are
compared as sets; the signed-in page does not re-issue the SSO cookies, so
its cookies are not compared; the reference's login cookies after
ui_locales (login/i18n-ui-locales-cookies) belong to the login flow and are
not compared here.
"""

import json
import pathlib
import re
import secrets
import unittest
import urllib.parse

from fixture import ENDPOINT, ISSUER_BASE, AdminCase, requires_setting


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/account-settings-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"
MANY_LOCALES = ["en", "de", "fr", "ar", "pt-BR", "zh-CN", "ja", "fa", "he"]
FLAG_FIELDS = ("internationalizationEnabled", "supportedLocales", "defaultLocale", "editUsernameAllowed", "registrationEmailAsUsername")
REALMS = {
    "plain": {},
    "clients": {},
    "i18n": {"internationalizationEnabled": True, "supportedLocales": MANY_LOCALES, "defaultLocale": "de"},
    "pair": {"internationalizationEnabled": True, "supportedLocales": ["en", "de"]},
    "off": {"internationalizationEnabled": False, "supportedLocales": ["en", "de"], "defaultLocale": "de"},
    "edit": {"editUsernameAllowed": True},
    "email": {"registrationEmailAsUsername": True},
    "both": {"editUsernameAllowed": True, "registrationEmailAsUsername": True},
}
PROFILE_CASES = {
    "rename": lambda own: {"username": "renamed-user", "email": own["email"]},
    "taken-username": lambda own: {"username": "other-user", "email": own["email"]},
    "new-email": lambda own: {"username": own["username"], "email": "changed@example.invalid"},
    "taken-email": lambda own: {"username": own["username"], "email": "other@example.invalid"},
    "no-username": lambda own: {"email": "renamed@example.invalid"},
}


def unordered_locales(value):
    """Sorts supported locale lists, which are compared as sets."""
    if isinstance(value, dict):
        return {key: sorted(item) if key == "supportedLocales" and isinstance(item, list) else unordered_locales(item) for key, item in value.items()}
    return value


class SettingsCase(AdminCase):
    """Realms and users made once per class, so each test is a few exchanges."""

    password = secrets.token_urlsafe(30)
    realm_keys = ()
    users = ()

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
            if key in ("plain", "clients"):
                for client in ({"clientId": "named-app", "name": "Named App", "description": "Shows a name", "publicClient": True, "redirectUris": [CALLBACK], "baseUrl": CALLBACK}, {"clientId": "plain-app", "publicClient": True, "redirectUris": [CALLBACK], "baseUrl": CALLBACK}):
                    assert cls.admin("POST", f"/admin/realms/{cls.names[key]}/clients", client)[0] == 201, client["clientId"]
            for username, email in cls.users:
                user = {"username": username, "enabled": True, "firstName": "Reference", "lastName": "User", "email": email, "emailVerified": True, "credentials": [{"type": "password", "value": cls.password, "temporary": False}]}
                assert cls.admin("POST", f"/admin/realms/{cls.names[key]}/users", user)[0] == 201, (key, username)

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

    def setUp(self):
        """The class's realms replace the per-test realm."""

    def tearDown(self):
        """The class's realms are removed with the class."""

    def sign_in(self, key, username="reference-user"):
        name = self.names[key]
        return self.browser_session(name, "account-console", f"{ISSUER_BASE}/realms/{name}/account/", username, self.password)

    def account(self, key, token, path="/", method="GET", payload=None):
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        status, _, body = self.request(method, f"/realms/{self.names[key]}/account" + path, headers, body=json.dumps(payload) if payload is not None else None)
        return status, json.loads(body) if body else None

    def realm_fields(self, key):
        _, realm = self.admin("GET", "/admin/realms/" + self.names[key])
        return {field: realm.get(field, "<absent>") for field in FLAG_FIELDS}

    def page(self, key, headers=None, query=None):
        path = f"/realms/{self.names[key]}/account/" + ("?" + urllib.parse.urlencode(query) if query else "")
        status, pairs, body = self.request_all("GET", path, headers)
        text = body.decode()
        env = json.loads(re.search(r'<script id="environment" type="application/json">(.*?)</script>', text, re.S).group(1))
        return {"status": status, "html": re.search(r"<html[^>]*>", text).group(0), "locale": env["locale"], "content_language": dict((k.lower(), v) for k, v in pairs).get("content-language"), "referrerName": env["referrerName"], "features": {name: env["features"][name] for name in ("isRegistrationEmailAsUsername", "isEditUserNameAllowed", "isInternationalizationEnabled")}, "set_cookies": sorted(value.split("=", 1)[0] for k, value in pairs if k.lower() == "set-cookie")}

    def assert_page(self, label, key, headers=None, query=None, cookies_checked=True):
        observed, expected = self.page(key, headers, query), dict(REFERENCE[label])
        if not cookies_checked:
            observed.pop("set_cookies")
            expected.pop("set_cookies")
        self.assertEqual(observed, expected, label)


class AdminSettings(SettingsCase):
    realm_keys = ("plain", "i18n", "pair", "off", "edit", "email", "both")

    def test_internationalization_settings(self):
        for key in ("plain", "i18n", "pair", "off"):
            self.assertEqual(self.realm_fields(key), unordered_locales(REFERENCE["admin/realm/" + key]), key)

    def test_username_settings(self):
        for key in ("edit", "email", "both"):
            self.assertEqual(self.realm_fields(key), REFERENCE["admin/realm/" + key], key)


class AdminSettingUpdates(AdminCase):
    def update(self, label, payload):
        status, _, body = self.call("PUT", "/admin/realms/" + self.realm, payload)
        self.assertEqual({"status": status, "body": json.loads(body) if body else None}, REFERENCE[label], label)

    def fields(self, label):
        _, _, body = self.call("GET", "/admin/realms/" + self.realm)
        realm = json.loads(body)
        self.assertEqual({field: realm.get(field, "<absent>") for field in FLAG_FIELDS}, unordered_locales(REFERENCE[label]), label)

    def test_locale_updates(self):
        for step, payload in [("enable-i18n", {"internationalizationEnabled": True, "supportedLocales": ["fr", "en"], "defaultLocale": "fr"}), ("locales-only", {"supportedLocales": ["en", "de", "ja"]}), ("disable-i18n", {"internationalizationEnabled": False}), ("clear-default", {"defaultLocale": ""}), ("null-default", {"defaultLocale": None, "supportedLocales": None}), ("empty-locales", {"supportedLocales": []})]:
            self.update("admin/update/" + step, payload)
            self.fields("admin/update/after-" + step)

    def test_flag_updates_and_wrong_types(self):
        for step, payload in [("locales-text", {"supportedLocales": "de"}), ("i18n-text", {"internationalizationEnabled": "yes"}), ("flag-text", {"editUsernameAllowed": "yes"})]:
            self.update("admin/update/" + step, payload)
        self.update("admin/update/flags", {"editUsernameAllowed": True, "registrationEmailAsUsername": True})
        _, _, body = self.call("GET", "/admin/realms/" + self.realm)
        realm = json.loads(body)
        expected = REFERENCE["admin/update/after-flags"]
        self.assertEqual({field: realm[field] for field in ("editUsernameAllowed", "registrationEmailAsUsername")}, {field: expected[field] for field in ("editUsernameAllowed", "registrationEmailAsUsername")})

    def test_users_take_the_email_as_username(self):
        self.update("admin/update/flags", {"editUsernameAllowed": True, "registrationEmailAsUsername": True})
        for username, email in (("reference-user", "reference@example.invalid"), ("other-user", "other@example.invalid")):
            self.assertEqual(self.call("POST", f"/admin/realms/{self.realm}/users", {"username": username, "enabled": True, "email": email})[0], 201)
        _, _, body = self.call("GET", f"/admin/realms/{self.realm}/users?briefRepresentation=true")
        self.assertEqual(sorted([user["username"], user.get("email")] for user in json.loads(body)), REFERENCE["admin/users/both"])


class ClientNames(SettingsCase):
    realm_keys = ("plain",)

    def client(self, client_id):
        _, found = self.admin("GET", f"/admin/realms/{self.names['plain']}/clients?clientId={client_id}")
        return {field: found[0].get(field, "<absent>") for field in ("name", "description")}, found[0]["id"]

    def test_stored_and_built_in_names(self):
        self.assertEqual(self.client("named-app")[0], REFERENCE["admin/client/named"])
        self.assertEqual(self.client("plain-app")[0], REFERENCE["admin/client/plain"])
        self.assertEqual({client: self.client(client)[0] for client in ("account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console")}, REFERENCE["admin/client/built-in"])

    def test_name_updates(self):
        _, named = self.client("named-app")
        for label, payload in [("rename", {"name": "Renamed App", "description": "Changed"}), ("clear", {"name": "", "description": ""}), ("null", {"name": None, "description": None}), ("restore", {"name": "Named App", "description": "Shows a name"})]:
            status, _ = self.admin("PUT", f"/admin/realms/{self.names['plain']}/clients/{named}", payload)
            self.assertEqual({"status": status, "after": self.client("named-app")[0]}, REFERENCE["admin/client/" + label], label)

    def test_number_name(self):
        # Its own client, so the other tests see plain-app unnamed.
        self.admin("POST", f"/admin/realms/{self.names['plain']}/clients", {"clientId": "number-app", "publicClient": True})
        _, number = self.client("number-app")
        status, _ = self.admin("PUT", f"/admin/realms/{self.names['plain']}/clients/{number}", {"name": 7})
        self.assertEqual({"status": status, "after": self.client("number-app")[0]}, REFERENCE["admin/client/number-name"])


@requires_setting("RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR")
class ConsoleClientNames(SettingsCase):
    realm_keys = ("plain", "clients")
    users = (("reference-user", "reference@example.invalid"),)

    def test_referrer_follows_the_client_name(self):
        _, found = self.admin("GET", f"/admin/realms/{self.names['clients']}/clients?clientId=named-app")
        path = f"/admin/realms/{self.names['clients']}/clients/{found[0]['id']}"
        self.assert_page("page/referrer-named", "clients", query={"referrer": "named-app"})
        self.assert_page("page/referrer-plain", "clients", query={"referrer": "plain-app"})
        self.admin("PUT", path, {"name": "Renamed App", "description": "Changed"})
        self.assert_page("page/referrer-renamed", "clients", query={"referrer": "named-app"})
        self.admin("PUT", path, {"name": "", "description": ""})
        self.assert_page("page/referrer-cleared", "clients", query={"referrer": "named-app"})

    def test_applications_show_names_and_descriptions(self):
        _, found = self.admin("GET", f"/admin/realms/{self.names['plain']}/clients?clientId=plain-app")
        # The recording renamed plain-app to 7 before listing applications.
        self.admin("PUT", f"/admin/realms/{self.names['plain']}/clients/{found[0]['id']}", {"name": 7})
        tokens, jar = self.sign_in("plain")
        for client in ("named-app", "plain-app"):
            self.sso_login(self.names["plain"], client, CALLBACK, jar)
        _, listed = self.account("plain", tokens["access_token"], "/applications")
        self.assertEqual(sorted([item["clientId"], item.get("clientName", "<absent>"), item.get("description", "<absent>")] for item in listed), REFERENCE["account/applications"])


@requires_setting("RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR")
class ConsoleLocales(SettingsCase):
    realm_keys = ("plain", "i18n", "pair", "off", "edit", "email", "both")

    def test_accept_language(self):
        for label, value in [("no-header", None), ("accept-de-de", "de-DE,de;q=0.9"), ("accept-fr", "fr"), ("accept-unsupported", "it, en;q=0.5"), ("accept-none-supported", "it"), ("accept-pt", "pt"), ("accept-pt-pt", "pt-PT"), ("accept-zh-tw", "zh-TW"), ("accept-zh", "zh"), ("accept-quality", "fr;q=0.2, ja;q=0.8"), ("accept-uppercase", "FR"), ("accept-wildcard", "*")]:
            self.assert_page("page/i18n/" + label, "i18n", {"Accept-Language": value} if value else None)

    def test_direction_cookie_and_query(self):
        for label, value in [("accept-ar", "ar"), ("accept-fa", "fa-IR"), ("accept-he", "he")]:
            self.assert_page("page/i18n/" + label, "i18n", {"Accept-Language": value})
        self.assert_page("page/i18n/cookie-fr", "i18n", {"Cookie": "KEYCLOAK_LOCALE=fr", "Accept-Language": "ja"})
        self.assert_page("page/i18n/cookie-unsupported", "i18n", {"Cookie": "KEYCLOAK_LOCALE=it", "Accept-Language": "ja"})
        self.assert_page("page/i18n/kc-locale", "i18n", {"Accept-Language": "ja"}, {"kc_locale": "fr"})

    def test_other_realms(self):
        for label, key, value in [("page/pair/no-header", "pair", None), ("page/pair/accept-de", "pair", "de"), ("page/pair/accept-fr", "pair", "fr"), ("page/off/accept-de", "off", "de"), ("page/plain/accept-de", "plain", "de")]:
            self.assert_page(label, key, {"Accept-Language": value} if value else None)

    def test_username_features(self):
        for key in ("plain", "edit", "email", "both"):
            self.assert_page("page/flags/" + key, key)


class SupportedLocales(SettingsCase):
    realm_keys = ("plain", "i18n", "pair", "off")
    users = (("reference-user", "reference@example.invalid"),)

    def check(self, key):
        tokens, _ = self.sign_in(key)
        status, listed = self.account(key, tokens["access_token"], "/supportedLocales")
        expected = REFERENCE["account/supported-locales/" + key]
        self.assertEqual({"status": status, "body": sorted(listed)}, {"status": expected["status"], "body": sorted(expected["body"])})

    def test_many_locales(self):
        self.check("i18n")

    def test_two_locales(self):
        self.check("pair")

    def test_internationalization_off(self):
        self.check("off")

    def test_no_locales(self):
        self.check("plain")


@requires_setting("RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR")
class UserLocale(SettingsCase):
    realm_keys = ("plain", "i18n")
    users = (("reference-user", "reference@example.invalid"), ("chooser-user", "chooser@example.invalid"), ("dropper-user", "dropper@example.invalid"))
    body = {"firstName": "Reference", "lastName": "User"}

    def own(self, username):
        return self.body | {"username": username, "email": username.replace("-user", "@example.invalid")}

    def test_profile_offers_the_locale(self):
        tokens, jar = self.sign_in("i18n")
        _, profile = self.account("i18n", tokens["access_token"], "/?userProfileMetadata=true")
        expected = REFERENCE["account/i18n/profile"]
        attributes = profile["userProfileMetadata"]["attributes"]
        self.assertEqual({"fields": sorted(profile), "attributes": profile.get("attributes", "<absent>"), "metadata_names": [item["name"] for item in attributes], "locale_metadata": attributes[0]}, expected)
        identity = {"Cookie": "; ".join(f"{k}={v}" for k, v in jar.items())}
        self.assert_page("page/i18n/signed-in", "i18n", identity | {"Accept-Language": "fr"}, cookies_checked=False)

    def set_locale(self, label, token, username, attributes):
        status, body = self.account("i18n", token, "/", "POST", self.own(username) | {"attributes": attributes})
        _, profile = self.account("i18n", token, "/")
        self.assertEqual({"status": status, "body": body, "attributes": profile.get("attributes", "<absent>")}, REFERENCE[label], label)

    def test_chosen_locale_leads(self):
        tokens, jar = self.sign_in("i18n", "chooser-user")
        identity = {"Cookie": "; ".join(f"{k}={v}" for k, v in jar.items()), "Accept-Language": "fr"}
        self.set_locale("account/i18n/set-locale", tokens["access_token"], "chooser-user", {"locale": ["ar"]})
        self.assert_page("page/i18n/signed-in-with-locale", "i18n", identity, cookies_checked=False)

    def test_unsupported_and_dropped_locale(self):
        tokens, jar = self.sign_in("i18n", "dropper-user")
        identity = {"Cookie": "; ".join(f"{k}={v}" for k, v in jar.items()), "Accept-Language": "fr"}
        self.set_locale("account/i18n/set-unsupported-locale", tokens["access_token"], "dropper-user", {"locale": ["it"]})
        self.assert_page("page/i18n/signed-in-unsupported-locale", "i18n", identity, cookies_checked=False)
        self.set_locale("account/i18n/drop-locale", tokens["access_token"], "dropper-user", {})

    def test_locale_ignored_without_internationalization(self):
        tokens, _ = self.sign_in("plain")
        status, body = self.account("plain", tokens["access_token"], "/", "POST", self.own("reference-user") | {"attributes": {"locale": ["ar"]}})
        _, profile = self.account("plain", tokens["access_token"], "/")
        self.assertEqual({"status": status, "body": body, "attributes": profile.get("attributes", "<absent>")}, REFERENCE["account/plain/set-locale"])


class ProfileRules(SettingsCase):
    """One user per case, as recorded, so no case sees another's changes."""

    realm_keys = ("plain", "edit", "email", "both")
    users = tuple((case + "-user", case + "@example.invalid") for case in ("metadata", *PROFILE_CASES)) + (("other-user", "other@example.invalid"),)

    def login_name(self, key, case):
        return case + ("@example.invalid" if key in ("email", "both") else "-user")

    def metadata(self, key):
        tokens, _ = self.sign_in(key, self.login_name(key, "metadata"))
        _, profile = self.account(key, tokens["access_token"], "/?userProfileMetadata=true")
        metadata = {item["name"]: item if item["name"] in ("username", "email") else {field: item.get(field) for field in ("required", "readOnly")} for item in profile["userProfileMetadata"]["attributes"]}
        self.assertEqual({"username": profile.get("username"), "email": profile.get("email"), "attributes": metadata}, REFERENCE[f"profile/{key}/metadata"])

    def update(self, key, case):
        tokens, _ = self.sign_in(key, self.login_name(key, case))
        token = tokens["access_token"]
        _, own = self.account(key, token)
        status, body = self.account(key, token, "/", "POST", PROFILE_CASES[case](own) | {"firstName": "Reference", "lastName": "User"})
        _, after = self.account(key, token)
        self.assertEqual({"before": [own["username"], own["email"]], "status": status, "body": body, "after": [after.get("username"), after.get("email")]}, REFERENCE[f"profile/{key}/{case}"])


for _key in ProfileRules.realm_keys:
    setattr(ProfileRules, f"test_{_key}_metadata", lambda self, key=_key: self.metadata(key))
    for _case in PROFILE_CASES:
        setattr(ProfileRules, f"test_{_key}_{_case.replace('-', '_')}", lambda self, key=_key, case=_case: self.update(key, case))


if __name__ == "__main__":
    unittest.main()
