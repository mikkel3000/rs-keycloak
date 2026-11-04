"""Browser SSO cookies and prompts compared with recorded Keycloak 26.8.1.

Expected cases come from tests/reference/sso-observations.json. The max_age=0
case needs a one-second wait, which exceeds the per-case budget; its rule is
unit-tested in crates/http/src/oidc.rs instead.
"""

import base64
import hashlib
import json
import pathlib
import re
import secrets
import unittest
import urllib.parse

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/sso-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"
SSO_COOKIES = ("KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION")


def parse_cookies(pairs, realm):
    cookies, jar = [], {}
    for name, value in pairs:
        if name.lower() != "set-cookie":
            continue
        cookie_name, _, rest = value.partition("=")
        if cookie_name not in SSO_COOKIES:
            continue
        cookie_value = rest.split(";", 1)[0]
        parts = [part.strip() for part in rest.split(";")[1:] if part.strip()]
        path = next(part[5:] for part in parts if part.lower().startswith("path="))
        max_age = next((part[8:] for part in parts if part.lower().startswith("max-age=")), None)
        cookies.append({
            "name": cookie_name,
            # Java's cookie writer adds a Version attribute that browsers ignore.
            "attributes": sorted({part.split("=", 1)[0].lower() for part in parts} | {"version"}),
            "path": path.replace(f"/realms/{realm}/", "/realms/{realm}/"),
            "cleared": max_age == "0",
        })
        jar[cookie_name] = cookie_value
    return sorted(cookies, key=lambda cookie: cookie["name"]), jar


class SsoContract(AdminCase):
    def setUp(self):
        super().setUp()
        clients = f"/admin/realms/{self.realm}/clients"
        for name in ("sso-app", "sso-other"):
            self.assertEqual(self.call("POST", clients, {"clientId": name, "publicClient": True, "redirectUris": [CALLBACK], "attributes": {"post.logout.redirect.uris": "+"}})[0], 201)
        user = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "reference-user", "enabled": True})[1]["location"].rsplit("/", 1)[1]
        self.password = secrets.token_urlsafe(32)
        self.call("PUT", f"/admin/realms/{self.realm}/users/{user}/reset-password", {"type": "password", "value": self.password})
        self.endpoint = f"/realms/{self.realm}/protocol/openid-connect"

    def authorize(self, client="sso-app", jar=None, **extra):
        self.verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).rstrip(b"=").decode()
        query = urllib.parse.urlencode(dict({"client_id": client, "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": challenge, "code_challenge_method": "S256"}, **extra))
        headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in jar.items())} if jar else {}
        return self.request_all("GET", f"{self.endpoint}/auth?{query}", headers)

    def assert_redirect(self, response, label):
        status, pairs, _ = response
        expected = REFERENCE[label]
        self.assertEqual(status, expected["status"], label)
        location = urllib.parse.urlsplit(dict((k.lower(), v) for k, v in pairs)["location"])
        params = urllib.parse.parse_qs(location.query)
        self.assertEqual(sorted(params), expected["location_params"], label)
        self.assertEqual(params.get("error", [None])[0], expected["error"], label)
        return params

    def exchange(self, client, params):
        status, _, body = self.request("POST", self.endpoint + "/token", form={"grant_type": "authorization_code", "code": params["code"][0], "client_id": client, "redirect_uri": CALLBACK, "code_verifier": self.verifier})
        self.assertEqual(status, 200)
        return json.loads(body)

    def login(self):
        status, pairs, body = self.authorize()
        self.assertEqual(status, 200)
        headers = dict((k.lower(), v) for k, v in pairs)
        action = re.search(r'action="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        csrf = headers["set-cookie"].split(";", 1)[0]
        response = self.request_all("POST", action, {"Cookie": csrf}, {"username": "reference-user", "password": self.password})
        cookies, jar = parse_cookies(response[1], self.realm)
        self.assertEqual(sorted(jar), REFERENCE["login/cookie-names"])
        self.assertEqual(cookies, REFERENCE["sso/same-client"]["cookies"])
        return self.exchange("sso-app", urllib.parse.parse_qs(urllib.parse.urlsplit(dict((k.lower(), v) for k, v in response[1])["location"]).query)), jar

    def test_prompt_none_without_session(self):
        self.assert_redirect(self.authorize(prompt="none"), "prompt-none/no-session")

    def test_session_issues_codes_without_the_form(self):
        first, jar = self.login()
        sid = self.verify(first["access_token"])["sid"]
        params = self.assert_redirect(self.authorize(jar=jar), "sso/same-client")
        self.assertEqual(params["session_state"], [sid])
        params = self.assert_redirect(self.authorize("sso-other", jar=jar), "sso/other-client")
        self.assertEqual(self.verify(self.exchange("sso-other", params)["access_token"])["sid"], sid)
        self.assert_redirect(self.authorize(jar=jar, prompt="none"), "prompt-none/with-session")
        self.assert_redirect(self.authorize(jar=jar, max_age="3600"), "sso/same-client")

    def test_prompt_login_shows_the_form(self):
        _, jar = self.login()
        status, _, body = self.authorize(jar=jar, prompt="login")
        expected = REFERENCE["prompt-login/with-session"]
        self.assertEqual((status, b"<form" in body), (expected["status"], expected["login_form"]))

    def test_logout_clears_cookies_and_ends_sso(self):
        first, jar = self.login()
        query = urllib.parse.urlencode({"id_token_hint": first["id_token"], "post_logout_redirect_uri": CALLBACK})
        status, pairs, _ = self.request_all("GET", f"{self.endpoint}/logout?{query}")
        expected = REFERENCE["logout/cookies"]
        self.assertEqual(status, expected["status"])
        self.assertEqual(parse_cookies(pairs, self.realm)[0], expected["cookies"])
        status, _, body = self.authorize(jar=jar)
        expected = REFERENCE["sso/after-logout"]
        self.assertEqual((status, b"<form" in body), (expected["status"], expected["login_form"]))


if __name__ == "__main__":
    unittest.main()
