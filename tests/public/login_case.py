"""A contract base for the login recordings made with
tests/reference/recording.py: realms with a public `login-app` client
made once per class, users, a tests/login_browser.py browser per realm,
and observations normalized as the recorder normalizes them."""

import json
import pathlib
import secrets
import sys
import urllib.parse

from fixture import ENDPOINT, ISSUER_BASE, AdminCase

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from login_browser import Browser  # noqa: E402

CALLBACK = ISSUER_BASE + "/callback"


def reference(baseline):
    return json.loads((pathlib.Path(__file__).resolve().parents[1] / "reference" / baseline).read_text())["observations"]


class LoginCase(AdminCase):
    """Subclasses set REALMS, a key to realm settings."""

    REALMS = {}
    password = secrets.token_urlsafe(30)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, _, body = cls.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": cls.ADMIN, "client_secret": cls.ADMIN_SECRET})
        assert status == 200, "admin token"
        cls.token = json.loads(body)["access_token"]
        prefix = "contract-" + secrets.token_hex(5)
        cls.names = {key: f"{prefix}-{key}" for key in cls.REALMS}
        for key, extra in cls.REALMS.items():
            assert cls.admin("POST", "/admin/realms", {"realm": cls.names[key], "enabled": True} | extra)[0] == 201, key
            assert cls.admin("POST", f"/admin/realms/{cls.names[key]}/clients", {"clientId": "login-app", "publicClient": True, "redirectUris": [CALLBACK]})[0] == 201, key

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
    def call_server(cls, method, path, headers=None, body=None):
        return cls.request_all(method, path, headers or {}, body=body)

    @classmethod
    def admin(cls, method, path, payload=None):
        headers = {"Authorization": "Bearer " + cls.token}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload)
        status, _, data = cls.request(method, path, headers, body=body)
        try:
            return status, json.loads(data) if data else None
        except ValueError:
            return status, data.decode()

    @classmethod
    def realm_admin(cls, key, path, method="GET", payload=None):
        return cls.admin(method, f"/admin/realms/{cls.names[key]}" + path, payload)

    @classmethod
    def new_user(cls, key, username, extra=None, password=True):
        """As the recorder makes users; fields `extra` sets to None are left
        out."""
        user = {"username": username, "enabled": True, "firstName": "Reference", "lastName": "User", "email": username.split("@")[0] + "@example.invalid", "emailVerified": True} | (extra or {})
        user = {field: value for field, value in user.items() if value is not None}
        if password:
            user["credentials"] = [{"type": "password", "value": cls.password, "temporary": False}]
        status, body = cls.realm_admin(key, "/users", "POST", user)
        assert status == 201, (key, username, status, body)
        _, found = cls.realm_admin(key, "/users?exact=true&username=" + urllib.parse.quote(username))
        return found[0]["id"]

    def browser(self, key):
        return Browser(self.call_server, ISSUER_BASE, self.names[key], CALLBACK)

    def normalized(self, observation):
        """Base URL and realm names as placeholders, as the recorder writes
        them."""
        text = json.dumps(observation).replace(ISSUER_BASE, "{base}")
        for key in sorted(self.names, key=lambda item: -len(self.names[item])):
            name = self.names[key]
            text = text.replace(name, "{realm-" + key + "}").replace(name[0].upper() + name[1:], "{Realm-" + key + "}")
        return json.loads(text)

    def shown(self, response):
        return self.normalized(self.browser(next(iter(self.names))).shown(response))
