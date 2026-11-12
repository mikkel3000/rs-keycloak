"""The account console compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/account-console-observations.json.
The console cases need RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR naming a directory
filled by compatibility/extract_account_console.py, and fail without it;
the server inherits the setting from this environment. Realm and client
settings are checked by account_settings_contract.py.

Known differences, listed in IMPLEMENTATION.md: group listings have only
the brief form.
"""

import base64
import hashlib
import json
import os
import pathlib
import re
import secrets
import unittest
import urllib.parse

from fixture import ISSUER_BASE, AdminCase, class_per_test, requires_setting


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/account-console-observations.json").read_text()
)["observations"]
CONSOLE = os.environ.get("RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR")
SKIPPED = {"date", "content-length", "set-cookie", "connection", "keep-alive", "transfer-encoding"}
ENTRY = "assets/main-YR-28UU6.js"
CALLBACK = "https://app.example.test/callback"
needs_console = requires_setting("RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR")


class ConsoleCase(AdminCase):
    version = None

    def clean(self, value):
        value = value.replace(ISSUER_BASE, "{base}").replace(self.realm, "{realm}")
        return value.replace(self.version, "{version}") if self.version else value

    def headers_of(self, pairs):
        return {name.lower(): self.clean(value) for name, value in sorted(pairs) if name.lower() not in SKIPPED}

    def get(self, path, headers=None, method="GET"):
        return self.request_all(method, path, headers)

    def environment(self, body):
        match = re.search(r'<script id="environment" type="application/json">(.*?)</script>', body.decode(), re.S)
        return json.loads(match.group(1))

    def page(self, path="", headers=None):
        status, pairs, body = self.get(f"/realms/{self.realm}/account/{path}", headers)
        if self.version is None and status == 200:
            ConsoleCase.version = self.environment(body)["resourceUrl"].split("/")[2]
        return status, pairs, body

    def sign_in(self):
        """Signs the reference user in to the console; returns tokens and cookies."""
        base = f"/admin/realms/{self.realm}"
        staff = self.call("POST", base + "/groups", {"name": "staff"})[1]["location"].rsplit("/", 1)[1]
        team = self.call("POST", f"{base}/groups/{staff}/children", {"name": "team"})[1]["location"].rsplit("/", 1)[1]
        user = self.call("POST", base + "/users", {"username": "reference-user", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "reference@example.invalid", "emailVerified": True})[1]["location"].rsplit("/", 1)[1]
        self.assertEqual(self.call("PUT", f"{base}/users/{user}/groups/{team}")[0], 204)
        password = secrets.token_urlsafe(30)
        self.call("PUT", f"{base}/users/{user}/reset-password", {"type": "password", "value": password})
        return self.browser_session(self.realm, "account-console", f"{ISSUER_BASE}/realms/{self.realm}/account/", "reference-user", password)


@needs_console
class AccountConsolePage(ConsoleCase):
    def test_page_and_sub_paths(self):
        status, pairs, body = self.page()
        expected = REFERENCE["page"]
        self.assertEqual(status, expected["status"])
        self.assertEqual(self.headers_of(pairs), expected["headers"])
        self.assertEqual(self.clean(body.decode()), expected["body"])
        for label, path in [("page/sub-path", "personal-info"), ("page/deep-sub-path", "account-security/signing-in"), ("page/api-path-in-browser", "applications"), ("page/query", "?tab=1")]:
            status, pairs, other = self.page(path)
            self.assertEqual({"status": status, "same_body": other == body, "location": self.headers_of(pairs).get("location")}, REFERENCE[label], label)
        for label, path in [("page/no-slash", f"/realms/{self.realm}/account"), ("page/index-html", f"/realms/{self.realm}/account/index.html"), ("page/unknown-realm", "/realms/missing-realm/account/")]:
            status, pairs, other = self.get(path)
            headers = self.headers_of(pairs)
            self.assertEqual({"status": status, "content_type": headers.get("content-type"), "location": headers.get("location"), "same_body": other == body, "json_body": json.loads(other) if headers.get("content-type") == "application/json" else None}, REFERENCE[label], label)

    def test_referrer_and_scope(self):
        self.assertEqual(self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "plain-app", "name": "Plain App", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        for label, query in [("page/referrer", {"referrer": "plain-app", "referrer_uri": CALLBACK}), ("page/referrer-foreign-uri", {"referrer": "plain-app", "referrer_uri": "https://elsewhere.example.invalid/"}), ("page/referrer-unknown", {"referrer": "missing-app"}), ("page/scope", {"scope": "offline_access"})]:
            status, _, body = self.page("?" + urllib.parse.urlencode(query))
            env = self.environment(body)
            expected = dict(REFERENCE[label])
            # The reference's callback is on its own base; here it is CALLBACK.
            expected["referrerUrl"] = expected["referrerUrl"].replace("{base}/callback", CALLBACK)
            self.assertEqual({"status": status, "referrerName": env["referrerName"], "referrerUrl": env["referrerUrl"], "scope": env["scope"]}, expected, label)

    def test_signed_in_features_and_session_cookie(self):
        tokens, jar = self.sign_in()
        session = self.verify(tokens["access_token"])["sid"]
        self.assertEqual(jar.get("KEYCLOAK_SESSION") == base64url_sha384(session), REFERENCE["cookie/session"]["hash_of_session_state"])
        status, _, body = self.page(headers={"Cookie": "; ".join(f"{k}={v}" for k, v in jar.items())})
        expected = REFERENCE["page/signed-in"]
        env = self.environment(body)
        self.assertEqual((status, env["features"], env["locale"]), (expected["status"], expected["features"], expected["locale"]))


def base64url_sha384(value):
    return base64.urlsafe_b64encode(hashlib.sha384(value.encode()).digest()).rstrip(b"=").decode()


@needs_console
class AccountConsoleResources(ConsoleCase):
    def setUp(self):
        super().setUp()
        self.page()
        self.theme = f"/resources/{self.version}/account/keycloak.v3/"
        self.common = f"/resources/{self.version}/common/keycloak/"

    def check(self, label, path, headers=None):
        status, pairs, body = self.get(path, headers)
        self.assertEqual({"status": status, "headers": self.headers_of(pairs), "body_sha256": hashlib.sha256(body).hexdigest() if status == 200 else None}, REFERENCE[label], label)

    def test_theme_and_common_files(self):
        for label, path in [("asset/entry", ENTRY), ("asset/stylesheet", "assets/main-BigPikZE.css"), ("asset/font", "assets/RedHatDisplayVF-CYDHf1NI.woff2"), ("asset/source-map", ENTRY + ".map"), ("asset/favicon", "favicon.svg"), ("asset/content-json", "content.json")]:
            self.check(label, self.theme + path)
        for label, path in [("asset/common-react", "vendor/react/react.production.min.js"), ("asset/common-font", "vendor/patternfly-v3/fonts/OpenSans-Regular-webfont.woff2"), ("asset/common-css", "vendor/patternfly-v3/css/patternfly.min.css")]:
            self.check(label, self.common + path)

    def test_versions_and_caching(self):
        self.check("asset/if-none-match", self.theme + ENTRY, {"If-None-Match": self.version})
        self.check("asset/other-version-hashed", f"/resources/abcde/account/keycloak.v3/{ENTRY}")
        self.check("asset/other-version-plain", "/resources/abcde/account/keycloak.v3/favicon.svg")
        self.check("asset/other-version-common", "/resources/abcde/common/keycloak/vendor/react/react.production.min.js")
        self.check("asset/bad-version", "/resources/not-a-version!/account/keycloak.v3/favicon.svg")

    def test_unknown_and_unsafe_paths(self):
        for label, path in [("asset/unknown-file", self.theme + "assets/missing.js"), ("asset/unknown-theme", f"/resources/{self.version}/account/missing-theme/favicon.svg"), ("asset/unknown-type", f"/resources/{self.version}/nothing/keycloak.v3/favicon.svg"), ("asset/traversal", self.theme + "..%2f..%2fcommon/keycloak/vendor/react/react.production.min.js"), ("asset/directory", self.theme + "assets/"), ("asset/template", self.theme + "index.ftl"), ("asset/theme-properties", self.theme + "theme.properties"), ("asset/messages-file", self.theme + "messages/messages_en.properties")]:
            self.check(label, path)


@needs_console
class AccountConsoleMessages(ConsoleCase):
    def check(self, label, path, headers=None, method="GET"):
        status, pairs, body = self.get(path, headers, method)
        listed = json.loads(body) if status == 200 and body else None
        pairs_sorted = sorted([item["key"], item["value"]] for item in listed) if isinstance(listed, list) else None
        observed = {
            "status": status,
            "headers": self.headers_of(pairs),
            "count": len(listed) if isinstance(listed, list) else None,
            "item_fields": sorted({field for item in listed for field in item}) if isinstance(listed, list) else None,
            "sources": sorted({item.get("source") for item in listed if "source" in item}) if isinstance(listed, list) else None,
            "pairs_sha256": hashlib.sha256(json.dumps(pairs_sorted, ensure_ascii=False).encode()).hexdigest() if pairs_sorted is not None else None,
            "locale_names": {key: value for key, value in pairs_sorted if key.startswith("locale_")} if pairs_sorted is not None else None,
        }
        if label == "messages/by-locale":
            return {key: observed[key] for key in ("count", "pairs_sha256", "locale_names")}
        self.assertEqual(observed, REFERENCE[label], label)

    def test_every_locale_bundle(self):
        observed = {tag: self.check("messages/by-locale", f"/resources/{self.realm}/account/{tag}") for tag in REFERENCE["messages/by-locale"]}
        self.assertEqual(observed, REFERENCE["messages/by-locale"])

    def test_locale_fallback_source_and_cors(self):
        for label, locale in [("messages/en", "en"), ("messages/de", "de"), ("messages/de-DE", "de-DE"), ("messages/zh-Hant", "zh-Hant"), ("messages/unknown-locale", "xx"), ("messages/source", "en?source=true"), ("messages/theme-param", "en?theme=keycloak.v3")]:
            self.check(label, f"/resources/{self.realm}/account/{locale}")
        self.check("messages/unknown-type", f"/resources/{self.realm}/nothing/en")
        self.check("messages/unknown-realm", "/resources/missing-realm/account/en")
        self.check("messages/cors", f"/resources/{self.realm}/account/en", {"Origin": "https://app.example.invalid"})
        self.check("messages/preflight", f"/resources/{self.realm}/account/en", {"Origin": "https://app.example.invalid", "Access-Control-Request-Method": "GET"}, "OPTIONS")


class AccountConsoleIframes(ConsoleCase):
    """The iframes are OIDC endpoints and need no console directory."""

    def check(self, label, path):
        status, pairs, body = self.get(path)
        observed = {"status": status, "headers": self.headers_of(pairs), "body_sha256": hashlib.sha256(body).hexdigest() if status == 200 else None}
        expected = dict(REFERENCE[label])
        expected.pop("body", None)
        self.assertEqual(observed, expected, label)

    def test_iframe_pages(self):
        endpoints = f"/realms/{self.realm}/protocol/openid-connect/"
        self.check("iframe/3p-step1", endpoints + "3p-cookies/step1.html")
        self.check("iframe/3p-step2", endpoints + "3p-cookies/step2.html")
        self.check("iframe/3p-other-version", endpoints + "3p-cookies/step1.html?version=abcde")
        self.check("iframe/login-status", endpoints + "login-status-iframe.html")
        self.check("iframe/login-status-other-version", endpoints + "login-status-iframe.html?version=abcde")
        self.check("iframe/login-status-unknown-realm", "/realms/missing-realm/protocol/openid-connect/login-status-iframe.html")

    def test_iframe_with_resource_version(self):
        self.assertTrue(CONSOLE, "RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR must be set")
        self.page()
        self.check("iframe/3p-version", f"/realms/{self.realm}/protocol/openid-connect/3p-cookies/step1.html?version={self.version}")

    def test_login_status_origin_check(self):
        endpoints = f"/realms/{self.realm}/protocol/openid-connect/"
        for label, query in [("own-origin", {"client_id": "account-console", "origin": ISSUER_BASE}), ("foreign-origin", {"client_id": "account-console", "origin": "https://elsewhere.example.invalid"}), ("unknown-client", {"client_id": "missing-app", "origin": ISSUER_BASE}), ("no-origin", {"client_id": "account-console"}), ("no-client", {"origin": ISSUER_BASE})]:
            self.check("iframe/init/" + label, endpoints + "login-status-iframe.html/init?" + urllib.parse.urlencode(query))


@needs_console
class AccountConsoleApi(ConsoleCase):
    def setUp(self):
        super().setUp()
        self.tokens, _ = self.sign_in()

    def api(self, label, path, headers):
        status, pairs, body = self.get(f"/realms/{self.realm}/account" + path, headers)
        content_type = self.headers_of(pairs).get("content-type")
        parsed = json.loads(body) if body and (content_type or "").startswith("application/json") else None
        observed = {"status": status, "content_type": content_type, "json": parsed is not None, "is_page": body.startswith(b"<!doctype html>")}
        expected = {key: REFERENCE[label][key] for key in observed}
        self.assertEqual(observed, expected, label)
        return parsed

    def test_console_calls(self):
        bearer = {"Authorization": "Bearer " + self.tokens["access_token"]}
        console = bearer | {"Content-Type": "application/json"}
        profile = self.api("api/profile-with-metadata", "/?userProfileMetadata=true", console)
        expected = REFERENCE["api/profile-with-metadata"]
        self.assertEqual((sorted(profile), sorted(profile["userProfileMetadata"]), profile["userProfileMetadata"]), (expected["fields"], expected["metadata_fields"], expected["metadata"]))
        self.assertEqual(sorted(self.api("api/profile-without-metadata", "/", console)), REFERENCE["api/profile-without-metadata"]["fields"])
        self.api("api/profile-accept-json", "/", bearer | {"Accept": "application/json"})
        self.api("api/profile-no-json-headers", "/", bearer)
        self.api("api/credentials", "/credentials", console)
        self.api("api/credentials-no-json-headers", "/credentials", bearer)
        self.assertEqual(self.api("api/supported-locales", "/supportedLocales", console), REFERENCE["api/supported-locales"]["body"])
        groups = self.api("api/groups", "/groups", console)
        self.assertEqual([{key: value for key, value in item.items() if key not in ("id", "parentId")} | {"has_id": "id" in item, "has_parent_id": "parentId" in item} for item in groups], REFERENCE["api/groups"]["body"])
        self.assertEqual(self.api("api/linked-accounts", "/linked-accounts", console), REFERENCE["api/linked-accounts"]["body"])
        self.api("api/no-token-json", "/credentials", {"Content-Type": "application/json"})


class WithoutConsole(ConsoleCase):
    """Without the setting the console routes are absent and every account
    route answers as the API, whatever the request asks for."""

    @classmethod
    def setUpClass(cls):
        saved = os.environ.pop("RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR", None)
        try:
            super().setUpClass()
        finally:
            if saved is not None:
                os.environ["RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR"] = saved

    def test_console_routes_are_absent(self):
        self.assertEqual(self.get(f"/realms/{self.realm}/account/")[0], 401)
        self.assertEqual(self.get(f"/realms/{self.realm}/account/personal-info")[0], 404)
        self.assertEqual(self.get(f"/resources/{self.realm}/account/en")[0], 404)
        self.assertEqual(self.get("/resources/abcde/account/keycloak.v3/favicon.svg")[0], 404)


class_per_test(AccountConsoleApi, globals())

if __name__ == "__main__":
    unittest.main()
