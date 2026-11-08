"""Email login and duplicate emails compared with recorded Keycloak 26.8.1
behavior.

Expected cases come from tests/reference/login-email-observations.json: the
login form's username label, signing in and asking for a password reset
with a username or an email, several users sharing an email, the
uniqueness checks of admin user creation and update and UPDATE_PROFILE, and
how realm updates tie loginWithEmailAllowed, duplicateEmailsAllowed and
registrationEmailAsUsername. Realms are made once per class, and each test
replays its part of the recording in order. Every recorded case is
replayed.
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
from otp import Forms  # noqa: E402

REFERENCE = json.loads((pathlib.Path(__file__).resolve().parents[1] / "reference/login-email-observations.json").read_text())["observations"]
SETTINGS = {
    "default": {},
    "noemail": {"loginWithEmailAllowed": False},
    "dupes": {"duplicateEmailsAllowed": True},
    "dupes-noemail": {"duplicateEmailsAllowed": True, "loginWithEmailAllowed": False},
    "email-username": {"registrationEmailAsUsername": True},
    "email-username-noemail": {"registrationEmailAsUsername": True, "loginWithEmailAllowed": False},
}
CALLBACK = ISSUER_BASE + "/callback"
BASE_PATH = urllib.parse.urlsplit(ISSUER_BASE).path


class Browser:
    """One browser on the contract server: a cookie jar, following redirects
    inside login-actions."""

    def __init__(self, case, key):
        self.case, self.realm, self.cookies = case, case.names[key], {}

    def send(self, path, headers=None, method="GET", body=None):
        while True:
            sent = dict(headers or {})
            if self.cookies:
                sent["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            status, pairs, data = self.case.request_all(method, path, sent, body=body)
            for header, value in pairs:
                if header.lower() == "set-cookie":
                    cookie, _, rest = value.partition("=")
                    content = rest.split(";", 1)[0]
                    if content and "max-age=0" not in value.lower():
                        self.cookies[cookie] = content
                    else:
                        self.cookies.pop(cookie, None)
            found = {k.lower(): v for k, v in pairs}
            target = urllib.parse.urlsplit(urllib.parse.urljoin(ISSUER_BASE + "/", found.get("location", "")))
            if status not in (302, 303) or "/login-actions/" not in target.path:
                return status, found, data
            path, method, body = target.path + ("?" + target.query if target.query else ""), "GET", None
            headers = {}

    def authorize(self):
        verifier = secrets.token_urlsafe(48)
        query = urllib.parse.urlencode({"client_id": "login-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": b64(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"})
        return self.send(f"/realms/{self.realm}/protocol/openid-connect/auth?" + query)

    def submit(self, response, fields):
        forms = Forms()
        forms.feed(response[2].decode())
        form = forms.forms[0]
        action = urllib.parse.urlsplit(urllib.parse.urljoin(ISSUER_BASE + "/", form["action"].replace("&amp;", "&")))
        target = action.path + ("?" + action.query if action.query else "")
        return self.send(target, {"Content-Type": "application/x-www-form-urlencoded"}, "POST", urllib.parse.urlencode(form["fields"] | fields))


class LoginEmailCase(AdminCase):
    password = secrets.token_urlsafe(30)
    realm_keys = tuple(SETTINGS)

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
            assert cls.admin("POST", "/admin/realms", {"realm": name, "enabled": True, "resetPasswordAllowed": True, "smtpServer": smtp} | SETTINGS[key])[0] == 201, key
            assert cls.admin("POST", f"/admin/realms/{name}/clients", {"clientId": "login-app", "publicClient": True, "redirectUris": [CALLBACK]})[0] == 201, key

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
    def admin_result(cls, key, path, method="GET", payload=None):
        status, body = cls.admin(method, f"/admin/realms/{cls.names[key]}" + path, payload)
        result = {"status": status}
        if isinstance(body, dict):
            result["body"] = {field: body[field] for field in ("errorMessage", "field", "params") if field in body}
        return result

    @classmethod
    def new_user(cls, key, username, email, extra=None):
        user = {"username": username, "enabled": True, "firstName": "Reference", "lastName": "User", "emailVerified": True, "credentials": [{"type": "password", "value": cls.password, "temporary": False}]} | ({"email": email} if email else {}) | (extra or {})
        status, body = cls.admin("POST", f"/admin/realms/{cls.names[key]}/users", user)
        assert status == 201, (key, username, body)
        _, found = cls.admin("GET", f"/admin/realms/{cls.names[key]}/users?exact=true&username=" + urllib.parse.quote(username))
        return found[0]["id"]

    def normalized(self, value):
        text = json.dumps(value)
        for key in sorted(self.names, key=lambda item: -len(self.names[item])):
            text = text.replace(self.names[key], "{realm-" + key + "}")
        return json.loads(text)

    def shown(self, response):
        status, headers, data = response
        if status in (302, 303):
            target = urllib.parse.urlsplit(headers.get("location", ""))
            path = target.path.removeprefix(BASE_PATH) if target.netloc else target.path
            return {"status": status, "location": path, "code": "code" in urllib.parse.parse_qs(target.query)}
        texts = page_texts(data)
        return {"status": status} | {key: value for key, value in texts.items() if key != "languages" and value not in (None, [], {})}

    def sign_in(self, key, login):
        browser = Browser(self, key)
        return self.shown(browser.submit(browser.authorize(), {"username": login, "password": self.password}))

    def check(self, label, observed):
        self.assertEqual(self.normalized(observed), REFERENCE[label], label)


class SettingsContract(LoginEmailCase):
    def test_representation_and_labels(self):
        for key in ("default", "dupes-noemail"):
            status, realm = self.admin("GET", f"/admin/realms/{self.names[key]}")
            self.check(f"representation/{key}", {"status": status, "loginWithEmailAllowed": realm.get("loginWithEmailAllowed"), "duplicateEmailsAllowed": realm.get("duplicateEmailsAllowed")})
        for key in SETTINGS:
            self.check(f"login-form/{key}", self.shown(Browser(self, key).authorize()))

    def test_realm_updates_turn_off_excluded_settings(self):
        # Fresh realms, so the other tests see the settings they were made with.
        fresh = {key: f"{self.names[key]}-update" for key in ("default", "dupes", "email-username")}
        for key, name in fresh.items():
            self.assertEqual(self.admin("POST", "/admin/realms", {"realm": name, "enabled": True} | SETTINGS[key])[0], 201, key)
        self.addCleanup(lambda: [self.admin("DELETE", "/admin/realms/" + name) for name in fresh.values()])
        for label, key, changes in (
            ("duplicates-with-email-login", "email-username", {"duplicateEmailsAllowed": True, "loginWithEmailAllowed": True, "registrationEmailAsUsername": True}),
            ("email-login-alone", "email-username", {"loginWithEmailAllowed": True}),
            ("email-login-off", "default", {"loginWithEmailAllowed": False}),
            ("email-login-on", "dupes", {"loginWithEmailAllowed": True}),
        ):
            status, _ = self.admin("PUT", f"/admin/realms/{fresh[key]}", changes)
            _, realm = self.admin("GET", f"/admin/realms/{fresh[key]}")
            observed = {"status": status} | {field: realm.get(field) for field in ("loginWithEmailAllowed", "duplicateEmailsAllowed", "registrationEmailAsUsername")}
            self.check(f"realm-update/{label}", observed)


class SignInContract(LoginEmailCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        for key in ("default", "noemail", "dupes", "dupes-noemail"):
            cls.new_user(key, "login-" + key, "login.mail@example.invalid")
        cls.new_user("email-username-noemail", "login@example.invalid", "login@example.invalid")

    def username_and_email(self, key):
        self.check(f"sign-in/{key}/username", self.sign_in(key, "login-" + key))
        self.check(f"sign-in/{key}/email", self.sign_in(key, "Login.Mail@example.invalid"))
        self.check(f"sign-in/{key}/email-lowercase", self.sign_in(key, "login.mail@example.invalid"))

    def test_default(self):
        self.username_and_email("default")

    def test_without_email_login(self):
        self.username_and_email("noemail")

    def test_with_duplicates(self):
        self.username_and_email("dupes")

    def test_with_duplicates_without_email_login(self):
        self.username_and_email("dupes-noemail")

    def test_email_as_username_without_email_login(self):
        self.check("sign-in/email-username-noemail/username", self.sign_in("email-username-noemail", "login@example.invalid"))


class CollisionContract(LoginEmailCase):
    def test_username_that_is_another_email(self):
        for key in ("default", "noemail"):
            self.new_user(key, "owner-" + key, "shared-name@example.invalid")
            status, body = self.admin("POST", f"/admin/realms/{self.names[key]}/users", {"username": "shared-name@example.invalid", "enabled": True, "firstName": "Reference", "lastName": "User", "email": f"at-user-{key}@example.invalid", "credentials": [{"type": "password", "value": self.password, "temporary": False}]})
            self.check(f"create/username-is-other-email/{key}", {"status": status, "body": {field: body[field] for field in ("errorMessage", "field", "params") if body and field in body}})
        # Without email login the username names its own user.
        self.check("sign-in/noemail/username-with-at", self.sign_in("noemail", "shared-name@example.invalid"))

    def test_update_profile_to_another_email(self):
        for key in ("default", "dupes"):
            self.new_user(key, "taken-" + key, "taken@example.invalid")
            self.new_user(key, "profile-" + key, "profile-" + key + "@example.invalid", {"requiredActions": ["UPDATE_PROFILE"]})
            browser = Browser(self, key)
            page = browser.submit(browser.authorize(), {"username": "profile-" + key, "password": self.password})
            self.check(f"update-profile/to-shared-email/{key}", self.shown(browser.submit(page, {"firstName": "Reference", "lastName": "User", "email": "taken@example.invalid"})))


class SharedEmailContract(LoginEmailCase):
    """Several users with one email: setUpClass makes them, recording the
    creation answers, and the tests check them and use the users."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.created = {}
        for key in ("default", "dupes", "dupes-noemail"):
            cls.new_user(key, "first-" + key, "twice@example.invalid")
            cls.created[f"create/duplicate-email/{key}"] = cls.admin_result(key, "/users", "POST", {"username": "second-" + key, "email": "TWICE@example.invalid", "enabled": True, "firstName": "Reference", "lastName": "User", "credentials": [{"type": "password", "value": cls.password, "temporary": False}]})
            cls.created[f"create/email-is-other-username/{key}"] = cls.admin_result(key, "/users", "POST", {"username": "third-" + key, "email": "first-" + key, "enabled": True})
        cls.others = {key: cls.new_user(key, "other-" + key, "other@example.invalid") for key in ("default", "dupes")}

    def test_creation(self):
        for label, observed in self.created.items():
            self.check(label, observed)

    def test_sign_in(self):
        self.check("sign-in/dupes/shared-email", self.sign_in("dupes", "twice@example.invalid"))
        self.check("sign-in/dupes/second-username", self.sign_in("dupes", "second-dupes"))
        self.check("sign-in/dupes-noemail/shared-email", self.sign_in("dupes-noemail", "twice@example.invalid"))

    def test_update_and_search(self):
        for key in ("dupes", "default"):
            self.check(f"update/to-shared-email/{key}", self.admin_result(key, f"/users/{self.others[key]}", "PUT", {"email": "twice@example.invalid"}))
        _, found = self.admin("GET", f"/admin/realms/{self.names['dupes']}/users?email=twice@example.invalid&exact=true")
        self.assertEqual(sorted(user["username"] for user in found), REFERENCE["search/shared-email/dupes"])


class LaterContract(LoginEmailCase):
    """Users made while duplicates were allowed, after email login turns on."""

    def test_shared_email_after_duplicates_end(self):
        for username in ("first-dupes", "second-dupes"):
            self.new_user("dupes", username, "twice@example.invalid")
        self.assertEqual(self.admin("PUT", f"/admin/realms/{self.names['dupes']}", {"loginWithEmailAllowed": True})[0], 204)
        self.check("sign-in/dupes-later/shared-email", self.sign_in("dupes", "twice@example.invalid"))
        self.check("sign-in/dupes-later/shared-email-username", self.sign_in("dupes", "first-dupes"))
        self.check("create/dupes-later/shared-email", self.admin_result("dupes", "/users", "POST", {"username": "fourth-dupes", "email": "twice@example.invalid", "enabled": True}))


class ResetContract(LoginEmailCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.new_user("default", "login-default", "login.mail@example.invalid")
        cls.new_user("noemail", "login-noemail", "login.mail@example.invalid")
        for key in ("dupes", "dupes-noemail"):
            for username in ("first-" + key, "second-" + key):
                cls.new_user(key, username, "twice@example.invalid")

    def reset(self, key, login):
        browser = Browser(self, key)
        page = browser.authorize()
        forgot = re.search(r'href="([^"]*/login-actions/reset-credentials[^"]*)"', page[2].decode()).group(1).replace("&amp;", "&")
        parts = urllib.parse.urlsplit(forgot)
        form = browser.send(parts.path + "?" + parts.query)
        before = len(self.sink.received)
        result = self.shown(browser.submit(form, {"username": login}))
        # This server sends the mail before it answers, as the reference does.
        mails = self.sink.received[before:]
        self.check(f"reset/{key}/{login}", result | {"mailed_to": sorted(address for mail in mails for address in mail["to"])})

    def test_email_with_email_login(self):
        self.reset("default", "Login.Mail@example.invalid")

    def test_email_without_email_login(self):
        self.reset("noemail", "Login.Mail@example.invalid")

    def test_username_without_email_login(self):
        self.reset("noemail", "login-noemail")

    def test_shared_email(self):
        self.reset("dupes", "twice@example.invalid")
        self.reset("dupes-noemail", "twice@example.invalid")


if __name__ == "__main__":
    unittest.main()
