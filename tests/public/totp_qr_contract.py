"""The TOTP setup QR code compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/totp-qr-observations.json: what
the CONFIGURE_TOTP page's QR code holds and how it is drawn, read by
tests/qr_code.py, the issuer from the display name with ${key} resolved in
the user's locale, the manual mode and the links between the modes, and the
mode a failed code keeps. Realms and users are made once per class.
"""

import base64
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
import qr_code  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
from otp import Forms  # noqa: E402

REFERENCE = json.loads((pathlib.Path(__file__).resolve().parents[1] / "reference/totp-qr-observations.json").read_text())["observations"]
REALMS = {
    "named": {"displayName": "${realmName}", "internationalizationEnabled": True, "supportedLocales": ["en", "de"], "defaultLocale": "en", "localizationTexts": {"en": {"realmName": "Realm: Name EN"}, "de": {"realmName": "Realm Name DE"}}},
    "plain": {},
    "colon": {"displayName": "A:B & C+D/é"},
}
CALLBACK = ISSUER_BASE + "/callback"


def base32(data):
    return base64.b32encode(data).decode().rstrip("=")


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
            found = {k.lower(): v for k, v in pairs}
            target = urllib.parse.urlsplit(urllib.parse.urljoin(ISSUER_BASE + "/", found.get("location", "")))
            if status not in (302, 303) or "/login-actions/" not in target.path:
                return status, found, data
            path, method, body = target.path + ("?" + target.query if target.query else ""), "GET", None
            headers = {}

    def visit(self, href):
        parts = urllib.parse.urlsplit(urllib.parse.urljoin(ISSUER_BASE + "/", href.replace("&amp;", "&")))
        return self.send(parts.path + ("?" + parts.query if parts.query else ""))

    def sign_in(self, login, query=None):
        self.verifier = secrets.token_urlsafe(48)
        params = {"client_id": "login-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": b64(hashlib.sha256(self.verifier.encode()).digest()), "code_challenge_method": "S256"} | (query or {})
        page = self.send(f"/realms/{self.realm}/protocol/openid-connect/auth?" + urllib.parse.urlencode(params))
        return self.submit(page, {"username": login, "password": self.case.password})

    def submit(self, response, fields):
        forms = Forms()
        forms.feed(response[2].decode())
        form = forms.forms[0]
        action = urllib.parse.urlsplit(urllib.parse.urljoin(ISSUER_BASE + "/", form["action"].replace("&amp;", "&")))
        target = action.path + ("?" + action.query if action.query else "")
        return self.send(target, {"Content-Type": "application/x-www-form-urlencoded"}, "POST", urllib.parse.urlencode(form["fields"] | fields))


class TotpQrCase(AdminCase):
    password = secrets.token_urlsafe(30)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, _, body = cls.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": cls.ADMIN, "client_secret": cls.ADMIN_SECRET})
        assert status == 200, "admin token"
        cls.token = json.loads(body)["access_token"]
        prefix = "contract-" + secrets.token_hex(5)
        cls.names = {key: f"{prefix}-{key}" for key in REALMS}
        for key, extra in REALMS.items():
            assert cls.admin("POST", "/admin/realms", {"realm": cls.names[key], "enabled": True} | extra)[0] == 201, key
            assert cls.admin("POST", f"/admin/realms/{cls.names[key]}/clients", {"clientId": "login-app", "publicClient": True, "redirectUris": [CALLBACK]})[0] == 201, key
        for key, username in (("named", "qr-user"), ("named", "ui-user"), ("plain", "name+tag@example.invalid"), ("colon", "colon-user")):
            cls.new_user(key, username, ["CONFIGURE_TOTP"])
        # The admin API keeps no user attributes, so the user sets the
        # locale through the account API before TOTP setup is asked for.
        user_id = cls.new_user("named", "de-user", [])
        browser = Browser(cls, "named")
        _, headers, _ = browser.sign_in("de-user")
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(headers["location"]).query)["code"][0]
        _, _, body = cls.request("POST", f"/realms/{cls.names['named']}/protocol/openid-connect/token", form={"grant_type": "authorization_code", "client_id": "login-app", "code": code, "redirect_uri": CALLBACK, "code_verifier": browser.verifier})
        access = json.loads(body)["access_token"]
        account = {"username": "de-user", "email": "de-user@example.invalid", "firstName": "Reference", "lastName": "User", "attributes": {"locale": ["de"]}}
        status, _, _ = cls.request("POST", f"/realms/{cls.names['named']}/account/", {"Authorization": "Bearer " + access, "Content-Type": "application/json"}, body=json.dumps(account))
        assert status == 204, f"account locale {status}"
        assert cls.admin("PUT", f"/admin/realms/{cls.names['named']}/users/{user_id}", {"requiredActions": ["CONFIGURE_TOTP"]})[0] == 204

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
    def new_user(cls, key, username, actions):
        user = {"username": username, "enabled": True, "firstName": "Reference", "lastName": "User", "email": username.replace("@", ".").replace("+", ".") + "@example.invalid", "emailVerified": True, "requiredActions": actions, "credentials": [{"type": "password", "value": cls.password, "temporary": False}]}
        assert cls.admin("POST", f"/admin/realms/{cls.names[key]}/users", user)[0] == 201, (key, username)
        _, found = cls.admin("GET", f"/admin/realms/{cls.names[key]}/users?exact=true&username=" + urllib.parse.quote(username))
        return found[0]["id"]

    def secret_of(self, response):
        forms = Forms()
        forms.feed(response[2].decode())
        return next(form for form in forms.forms if "totpSecret" in form["fields"])["fields"]

    def shown(self, response):
        """As the recorder reduces the page: texts, QR code, shown key and
        mode links, with the secret as a placeholder."""
        status, _, data = response
        text = data.decode()
        fields = self.secret_of(response)
        secret = fields["totpSecret"]
        encoded = base32(secret.encode())
        grouped = " ".join(encoded[i:i + 4] for i in range(0, len(encoded), 4))
        texts = json.loads(json.dumps(page_texts(data)).replace(grouped, "{key}"))
        texts["items"].sort()
        result = {"status": status, "mode_field": fields.get("mode")} | {key: value for key, value in texts.items() if key != "languages" and value not in (None, [], {})}
        image = re.search(r'<img[^>]*id="kc-totp-secret-qr-code"[^>]*src="data:image/png;base64,\s*([^"]+)"', text)
        if image:
            code = qr_code.read(base64.b64decode(image.group(1)))
            code["text"] = code["text"].replace(encoded, "{secret}")
            result["qr"] = code
        key = re.search(r'id="kc-totp-secret-key"[^>]*>([^<]*)<', text)
        if key:
            result["key"] = {"grouped": key.group(1).strip() == grouped, "length": len(key.group(1).strip())}
        result["secret_length"] = len(secret)
        modes = {}
        for link_id in ("mode-manual", "mode-barcode"):
            link = re.search(r'<a href="([^"]*)" id="' + link_id + '"', text)
            if link:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(link.group(1).replace("&amp;", "&")).query)
                modes[link_id] = {"path": urllib.parse.urlsplit(link.group(1)).path.rsplit("/", 1)[-1], "mode": query.get("mode"), "execution": query.get("execution")}
        result["mode_links"] = modes
        normalized = json.dumps(result)
        for realm_key in sorted(self.names, key=lambda item: -len(self.names[item])):
            normalized = normalized.replace(self.names[realm_key], "{realm-" + realm_key + "}")
        return json.loads(normalized)

    def link(self, response, link_id):
        return re.search(r'<a href="([^"]*)" id="' + link_id + '"', response[2].decode()).group(1)


class ModesContract(TotpQrCase):
    def test_qr_then_manual_then_qr(self):
        browser = Browser(self, "named")
        page = browser.sign_in("qr-user")
        self.assertEqual(self.shown(page), REFERENCE["qr/named/en"])
        manual = browser.visit(self.link(page, "mode-manual"))
        self.assertEqual(self.shown(manual), REFERENCE["manual/named/en"])
        self.assertEqual(self.shown(browser.submit(manual, {"totp": "", "userLabel": ""})), REFERENCE["manual-failed/named/en"])
        back = browser.visit(self.link(manual, "mode-barcode"))
        self.assertEqual(self.shown(back), REFERENCE["qr-again/named/en"])
        self.assertEqual(self.shown(browser.submit(back, {"totp": "", "userLabel": ""})), REFERENCE["qr-again-failed/named/en"])
        self.assertEqual(len({self.secret_of(response)["totpSecret"] for response in (page, manual, back)}) == 1, REFERENCE["same-secret"])


class IssuerContract(TotpQrCase):
    def test_issuer_in_the_user_locale(self):
        self.assertEqual(self.shown(Browser(self, "named").sign_in("de-user")), REFERENCE["qr/named/user-de"])

    def test_issuer_in_ui_locales(self):
        self.assertEqual(self.shown(Browser(self, "named").sign_in("ui-user", {"ui_locales": "de"})), REFERENCE["qr/named/ui-de"])

    def test_realm_name_and_encoded_account(self):
        self.assertEqual(self.shown(Browser(self, "plain").sign_in("name+tag@example.invalid")), REFERENCE["qr/plain"])

    def test_display_name_with_colon(self):
        self.assertEqual(self.shown(Browser(self, "colon").sign_in("colon-user")), REFERENCE["qr/colon"])


if __name__ == "__main__":
    unittest.main()
