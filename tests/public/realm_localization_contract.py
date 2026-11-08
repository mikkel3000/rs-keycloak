"""Realm localization texts compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/realm-localization-observations.json:
the admin /localization endpoints, texts given at realm creation and in a
partial export, and realm texts overriding the login theme on the login
page, an authorization error page and the logout confirmation. Realms are
made once per class, so each test is a few exchanges.

Known difference, listed in IMPLEMENTATION.md: rememberMe is not
implemented, so the login page's third label, "Remember me", is not
compared.
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

from fixture import ENDPOINT, ISSUER_BASE, ServerCase, cli

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from page_texts import page_texts  # noqa: E402

RECORDING = json.loads((pathlib.Path(__file__).resolve().parents[1] / "reference/realm-localization-observations.json").read_text())
REFERENCE = RECORDING["observations"]
PAGE_TEXTS = RECORDING["paired_texts"]
RUN = secrets.token_hex(4)
ADMIN, ADMIN_SECRET = "admin-client-" + RUN, secrets.token_urlsafe(40)
PLAIN, PLAIN_SECRET = "plain-client-" + RUN, secrets.token_urlsafe(40)
CALLBACK = ISSUER_BASE + "/callback"
SUPPORTED = ["en", "de", "de-CH", "fr"]


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class LocalizationCase(ServerCase):
    @classmethod
    def provision(cls):
        for client, secret in ((ADMIN, ADMIN_SECRET), (PLAIN, PLAIN_SECRET)):
            assert cli("client", "add-confidential", "master", client, "https://app.example.test/cb", stdin=secret + "\n").returncode == 0
            assert cli("client", "enable-service-account", "master", client).returncode == 0
        assert cli("client", "grant-master-admin", ADMIN).returncode == 0

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.admin_token = cls.token(ADMIN, ADMIN_SECRET)
        cls.unprivileged = cls.token(PLAIN, PLAIN_SECRET)
        prefix = "contract-" + secrets.token_hex(5)
        cls.names = {key: f"{prefix}-{key}" for key in ("api", "created", "pages", "plain")}
        realms = {
            "api": {"defaultLocale": "en"},
            "created": {"localizationTexts": {"en": {"key-a": "text-a_en", "key-b": "text-b_en"}, "de": {"key-a": "text-a_de"}}},
            "pages": {"displayName": "${realmName}", "internationalizationEnabled": True, "supportedLocales": SUPPORTED, "defaultLocale": "fr", "localizationTexts": PAGE_TEXTS},
            "plain": {"displayName": "Plain ${realmName}", "localizationTexts": {"en": {"realmName": "from texts", "doLogIn": "Plain go"}, "de": {"doLogIn": "Nicht gezeigt"}}},
        }
        for key, extra in realms.items():
            assert cls.json_call("POST", "/admin/realms", {"realm": cls.names[key], "enabled": True} | extra)[0] == 201, key
        for key in ("pages", "plain"):
            client = {"clientId": "login-app", "publicClient": True, "redirectUris": [CALLBACK]}
            assert cls.json_call("POST", f"/admin/realms/{cls.names[key]}/clients", client)[0] == 201, key

    @classmethod
    def tearDownClass(cls):
        for name in getattr(cls, "names", {}).values():
            cls.json_call("DELETE", "/admin/realms/" + name)
        super().tearDownClass()

    @classmethod
    def token(cls, client, secret):
        status, _, body = cls.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": client, "client_secret": secret})
        assert status == 200, "token"
        return json.loads(body)["access_token"]

    @classmethod
    def json_call(cls, method, path, payload=None):
        headers = {"Authorization": "Bearer " + cls.admin_token}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload)
        return cls.request(method, path, headers, body=body)

    def normalized(self, value):
        text = json.dumps(value).replace(ISSUER_BASE, "{base}")
        for key in sorted(self.names, key=lambda item: -len(self.names[item])):
            text = text.replace(self.names[key], "{realm-" + key + "}")
        return json.loads(text)

    def localization(self, label, realm_key, path="", method="GET", token=None, body=None, content_type=None):
        headers = {} if token is False else {"Authorization": "Bearer " + (token or self.admin_token)}
        if content_type:
            headers["Content-Type"] = content_type
        status, found, data = self.request(method, f"/admin/realms/{self.names[realm_key]}/localization" + path, headers, body=body)
        kind = found.get("content-type", "").split(";")[0].strip() or None
        result = {"status": status, "content_type": kind}
        if data and kind == "application/json":
            result["body"] = json.loads(data)
        elif data:
            result["text"] = data.decode()
        self.assertEqual(self.normalized(result), REFERENCE[label], label)

    def multipart(self, parts):
        boundary = "contract" + secrets.token_hex(8)
        chunks = []
        for name, filename, content in parts:
            disposition = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename else "")
            chunks.append(f"--{boundary}\r\nContent-Disposition: {disposition}\r\nContent-Type: application/json\r\n\r\n".encode() + content + b"\r\n")
        return b"".join(chunks) + f"--{boundary}--\r\n".encode(), "multipart/form-data; boundary=" + boundary

    def page(self, realm_key, language=None, query=None, client="login-app", logout=False):
        headers = {"Accept-Language": language} if language else {}
        realm = self.names[realm_key]
        if logout:
            path = f"/realms/{realm}/protocol/openid-connect/logout"
        else:
            verifier = secrets.token_urlsafe(48)
            params = {"client_id": client, "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": b64(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"}
            path = f"/realms/{realm}/protocol/openid-connect/auth?" + urllib.parse.urlencode(params | (query or {}))
        status, _, data = self.request("GET", path, headers)
        tag = re.search(r"<html[^>]*>", data.decode())
        lang = tag and re.search(r'\blang="([^"]*)"', tag.group(0))
        texts = page_texts(data)
        return {"status": status, "lang": lang and lang.group(1)} | {key: value for key, value in texts.items() if key != "languages" and value not in (None, [], {})}

    def check_page(self, label, observed):
        expected = REFERENCE[label]
        if label.startswith("login/") and "/plain/" not in label:
            # rememberMe is not implemented.
            expected = expected | {"labels": expected["labels"][:2]}
        self.assertEqual(self.normalized(observed), expected, label)


class AdminContract(LocalizationCase):
    def test_texts_lifecycle(self):
        call = self.localization
        call("locales/new", "api")
        call("locale/missing", "api", "/en")
        call("text/missing", "api", "/en/key-a")
        call("put/text", "api", "/en/key-a", "PUT", body=b"Text A", content_type="text/plain")
        call("put/json-type", "api", "/en/key-j", "PUT", body=b'"Text J"', content_type="application/json")
        call("put/empty", "api", "/en/key-e", "PUT", body=b"", content_type="text/plain")
        call("text/after-put", "api", "/en/key-a")
        call("text/empty", "api", "/en/key-e")
        call("put/replace", "api", "/en/key-a", "PUT", body=b"Text A2 \xc3\xa4", content_type="text/plain")
        call("text/after-replace", "api", "/en/key-a")
        call("post/merge", "api", "/en", "POST", body=json.dumps({"key-b": "Text B", "key-c": "Text C"}).encode(), content_type="application/json")
        call("locale/after-merge", "api", "/en")
        call("post/new-locale", "api", "/de", "POST", body=json.dumps({"key-a": "Text A de"}).encode(), content_type="application/json")
        call("post/empty-map", "api", "/pt-BR", "POST", body=b"{}", content_type="application/json")
        call("post/malformed", "api", "/de", "POST", body=b"{", content_type="application/json")
        call("post/not-strings", "api", "/de", "POST", body=b'{"key-n": 1}', content_type="application/json")
        call("locales/after-posts", "api")
        call("locale/fallback", "api", "/de?useRealmDefaultLocaleFallback=true")
        call("locale/no-fallback", "api", "/de?useRealmDefaultLocaleFallback=false")
        call("locale/unknown", "api", "/zz")
        data, kind = self.multipart([("file", "texts.json", json.dumps({"key-f": "Text F", "key-g": "Text G"}).encode())])
        call("upload/file", "api", "/fr", "POST", body=data, content_type=kind)
        call("locale/after-upload", "api", "/fr")
        data, kind = self.multipart([("other", "texts.json", b'{"key-x": "X"}')])
        call("upload/no-file", "api", "/fr", "POST", body=data, content_type=kind)
        data, kind = self.multipart([("file", "texts.json", b"not json")])
        call("upload/malformed", "api", "/fr", "POST", body=data, content_type=kind)
        call("delete/text", "api", "/en/key-b", "DELETE")
        call("delete/text-repeat", "api", "/en/key-b", "DELETE")
        call("delete/text-unknown-locale", "api", "/zz/key-b", "DELETE")
        call("delete/last-text", "api", "/de/key-a", "DELETE")
        call("locales/after-last-text", "api")
        call("locale/after-last-text", "api", "/de")
        call("delete/locale", "api", "/de", "DELETE")
        call("delete/locale-repeat", "api", "/de", "DELETE")
        call("locales/after-delete", "api")
        status, _, data = self.request("POST", f"/admin/realms/{self.names['api']}/partial-export", {"Authorization": "Bearer " + self.admin_token})
        self.assertEqual({"status": status, "localizationTexts": json.loads(data).get("localizationTexts")}, REFERENCE["api/partial-export"])

    def test_refusals(self):
        call = self.localization
        call("refused/no-token/locales", "api", token=False)
        call("refused/no-token/put", "api", "/en/key-z", "PUT", token=False, body=b"Z", content_type="text/plain")
        call("refused/unprivileged/locales", "api", token=self.unprivileged)
        call("refused/unprivileged/locale", "api", "/en", token=self.unprivileged)
        call("refused/unprivileged/text", "api", "/en/key-a", token=self.unprivileged)
        call("refused/unprivileged/put", "api", "/en/key-z", "PUT", token=self.unprivileged, body=b"Z", content_type="text/plain")
        call("refused/unprivileged/post", "api", "/en", "POST", token=self.unprivileged, body=b'{"key-z": "Z"}', content_type="application/json")
        call("refused/unprivileged/delete", "api", "/en", "DELETE", token=self.unprivileged)

    def test_texts_given_at_creation(self):
        call = self.localization
        call("created/locales", "created")
        call("created/en", "created", "/en")
        status, _, data = self.json_call("GET", f"/admin/realms/{self.names['created']}")
        self.assertEqual({"status": status, "has_localization_texts": "localizationTexts" in json.loads(data)}, REFERENCE["created/representation"])
        status, _, _ = self.json_call("PUT", f"/admin/realms/{self.names['created']}", {"localizationTexts": {"en": {"key-p": "from update"}}})
        self.assertEqual({"status": status}, REFERENCE["created/update-with-texts"])
        call("created/en-after-update", "created", "/en")
        status, _, data = self.request("POST", f"/admin/realms/{self.names['created']}/partial-export", {"Authorization": "Bearer " + self.admin_token})
        self.assertEqual({"status": status, "localizationTexts": json.loads(data).get("localizationTexts")}, REFERENCE["created/partial-export"])


class PagesContract(LocalizationCase):
    def test_login_pages(self):
        for language in ("en", "de", "de-CH", "fr"):
            self.check_page(f"login/{language}", self.page("pages", language))
        self.check_page("login/ui-de-CH", self.page("pages", query={"ui_locales": "de-CH"}))
        self.check_page("login/plain/de", self.page("plain", "de"))

    def test_error_and_logout_pages(self):
        for language in ("en", "de"):
            self.check_page(f"authorize-error/{language}", self.page("pages", language, client="missing-app"))
            self.check_page(f"logout-confirm/{language}", self.page("pages", language, logout=True))
        self.check_page("authorize-error/plain/de", self.page("plain", "de", client="missing-app"))


class ChangedTextsContract(LocalizationCase):
    def test_changed_texts_show_on_the_next_page(self):
        headers = {"Authorization": "Bearer " + self.admin_token, "Content-Type": "text/plain"}
        status, _, _ = self.request("PUT", f"/admin/realms/{self.names['pages']}/localization/en/loginAccountTitle", headers, body=b"Changed realm sign in")
        self.assertEqual(status, 204)
        self.request("DELETE", f"/admin/realms/{self.names['pages']}/localization/de-CH", {"Authorization": "Bearer " + self.admin_token})
        self.check_page("login/en-after-change", self.page("pages", "en"))
        self.check_page("login/de-CH-after-delete", self.page("pages", "de-CH"))


if __name__ == "__main__":
    unittest.main()
