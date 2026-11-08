"""OAuth consent compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/consent-observations.json. Granted
scopes differ: only openid is grantable here, where the reference lists its
default client scopes.
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
    (pathlib.Path(__file__).resolve().parents[1] / "reference/consent-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


class ConsentContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "consent-app", "publicClient": True, "consentRequired": True, "redirectUris": [CALLBACK]})[0], 201)
        location = self.call("POST", f"/admin/realms/{self.realm}/users", {"username": "reference-user", "enabled": True})[1]["location"]
        self.user = location.rsplit("/", 1)[1]
        self.password = secrets.token_urlsafe(32)
        self.call("PUT", f"/admin/realms/{self.realm}/users/{self.user}/reset-password", {"type": "password", "value": self.password})
        self.consents = f"/admin/realms/{self.realm}/users/{self.user}/consents"

    def authorize(self, jar, **extra):
        challenge = base64.urlsafe_b64encode(hashlib.sha256(secrets.token_bytes(16)).digest()).rstrip(b"=").decode()
        query = urllib.parse.urlencode(dict({"client_id": "consent-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": challenge, "code_challenge_method": "S256"}, **extra))
        return self.browse("GET", f"/realms/{self.realm}/protocol/openid-connect/auth?{query}", jar)

    def browse(self, method, path, jar, form=None):
        """Sends a request with the cookie jar and records cookies it sets."""
        headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in jar.items())} if jar else {}
        status, pairs, body = self.request_all(method, path, headers, form)
        for name, value in pairs:
            if name.lower() == "set-cookie":
                cookie_name, _, rest = value.partition("=")
                cookie_value = rest.split(";", 1)[0]
                if "Max-Age=0" in rest:
                    jar.pop(cookie_name, None)
                else:
                    jar[cookie_name] = cookie_value
        return status, dict((k.lower(), v) for k, v in pairs), body

    def login(self, jar, **extra):
        status, _, body = self.authorize(jar, **extra)
        self.assertEqual(status, 200)
        action = re.search(r'action="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        return self.browse("POST", action, jar, {"username": "reference-user", "password": self.password})

    def summarize(self, response):
        status, headers, body = response
        if status in (302, 303):
            params = urllib.parse.parse_qs(urllib.parse.urlsplit(headers["location"]).query)
            return {"status": status, "location_params": sorted(params), "error": params.get("error", [None])[0]}
        text = body.decode()
        page = "consent" if 'id="kc-oauth"' in text else "login" if 'name="password"' in text else "other"
        return {"status": status, "page": page, "buttons": sorted(re.findall(r'type="submit" name="([^"]+)"', text))}

    def answer(self, jar, response, button):
        action = re.search(r'action="([^"]+)"', response[2].decode()).group(1)
        return self.browse("POST", action, jar, {button: "x"})

    def test_deny_keeps_no_consent(self):
        jar = {}
        page = self.login(jar)
        self.assertEqual(self.summarize(page), REFERENCE["consent/after-password"])
        self.assertEqual(self.summarize(self.answer(jar, page, "cancel")), REFERENCE["consent/deny"])
        self.assertEqual(len(json.loads(self.call("GET", self.consents)[2])), REFERENCE["admin/consents-after-deny"]["count"])

    def test_accept_then_remembered(self):
        jar = {}
        page = self.login(jar)
        self.assertEqual(self.summarize(self.answer(jar, page, "accept")), REFERENCE["consent/accept"])
        granted = json.loads(self.call("GET", self.consents)[2])
        expected = REFERENCE["admin/consents-after-accept"]
        self.assertEqual((len(granted), sorted(granted[0]), granted[0]["clientId"]), (expected["count"], expected["fields"], expected["client"]))
        self.assertEqual(self.summarize(self.login({})), REFERENCE["consent/remembered"])

    def test_prompt_consent_and_revocation(self):
        jar = {}
        page = self.login(jar)
        self.answer(jar, page, "accept")
        self.assertEqual(self.summarize(self.authorize(jar, prompt="consent")), REFERENCE["consent/prompt-consent"])
        self.assertEqual(self.call("DELETE", self.consents + "/consent-app")[0], REFERENCE["admin/revoke-consent"]["status"])
        self.assertEqual(self.call("DELETE", self.consents + "/missing-app")[0], REFERENCE["admin/revoke-unknown"]["status"])
        self.assertEqual(self.summarize(self.login({})), REFERENCE["consent/after-revoke"])

    def test_sso_session_still_asks_for_missing_consent(self):
        jar = {}
        self.answer(jar, self.login(jar), "cancel")
        self.assertEqual(self.summarize(self.authorize(jar))["page"], "consent")


if __name__ == "__main__":
    unittest.main()
