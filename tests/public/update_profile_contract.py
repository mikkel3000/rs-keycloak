"""UPDATE_PROFILE compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/update-profile-observations.json.
"""

import json
import pathlib
import re
import secrets
import unittest
import urllib.parse

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/update-profile-observations.json").read_text()
)["observations"]
CALLBACK = "https://app.example.test/callback"


class UpdateProfileContract(AdminCase):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.call("POST", f"/admin/realms/{self.realm}/clients", {"clientId": "profile-app", "publicClient": True, "redirectUris": [CALLBACK]})[0], 201)
        users = f"/admin/realms/{self.realm}/users"
        self.user = self.call("POST", users, {"username": "reference-user", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "reference@example.invalid", "emailVerified": True, "requiredActions": ["UPDATE_PROFILE"]})[1]["location"].rsplit("/", 1)[1]
        self.call("POST", users, {"username": "other-user", "enabled": True, "email": "other@example.invalid"})
        self.password = secrets.token_urlsafe(30)
        self.call("PUT", f"{users}/{self.user}/reset-password", {"type": "password", "value": self.password})
        self.users = users

    def page(self, response):
        status, headers, body = response
        if status in (302, 303):
            return {"status": status, "location_params": sorted(urllib.parse.parse_qs(urllib.parse.urlsplit(headers["location"]).query)), "errors": []}, None, {}
        text = body.decode()
        form = re.search(r'<form id="([^"]+)"[^>]*action="([^"]+)"', text)
        inputs = dict(re.findall(r'<input name="([^"]+)"[^>]*value="([^"]*)"', text))
        errors = sorted(set(re.findall(r'id="input-error-([a-zA-Z-]+)"', text)))
        return {"status": status, "form": form.group(1), "fields": sorted(inputs), "errors": errors}, form.group(2).replace("&amp;", "&"), inputs

    def profile_page(self):
        """Signs in and returns the profile page, its form action and the
        browser's cookie."""
        query = urllib.parse.urlencode({"client_id": "profile-app", "redirect_uri": CALLBACK, "response_type": "code", "scope": "openid", "state": "s", "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"})
        status, headers, body = self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/auth?{query}")
        cookie = {"Cookie": headers["set-cookie"].split(";", 1)[0]}
        action = re.search(r'action="([^"]+)"', body.decode()).group(1).replace("&amp;", "&")
        observed, action, inputs = self.page(self.request("POST", action, cookie, {"username": "reference-user", "password": self.password}))
        return observed, action, inputs, cookie

    def test_profile_is_reviewed_and_validated(self):
        observed, action, inputs, cookie = self.profile_page()
        expected = REFERENCE["login/profile-page"]
        self.assertEqual((observed["status"], observed["form"], observed["fields"]), (expected["status"], expected["form"], expected["fields"]))
        self.assertEqual(sorted(name for name, value in inputs.items() if value), expected["prefilled"])
        for label, form in (
            ("update/missing-first-name", {"firstName": "", "lastName": "Changed", "email": "changed@example.invalid"}),
            ("update/invalid-email", {"firstName": "Changed", "lastName": "Changed", "email": "not-an-email"}),
            ("update/taken-email", {"firstName": "Changed", "lastName": "Changed", "email": "other@example.invalid"}),
        ):
            observed, action, _ = self.page(self.request("POST", action, cookie, form))
            self.assertEqual(observed, REFERENCE[label], label)

    def test_profile_is_saved(self):
        _, action, _, cookie = self.profile_page()
        observed, _, _ = self.page(self.request("POST", action, cookie, {"firstName": "Changed", "lastName": "Person", "email": "Changed@Example.invalid"}))
        self.assertEqual(observed, REFERENCE["update/success"])
        rep = json.loads(self.call("GET", f"{self.users}/{self.user}")[2])
        self.assertEqual({key: rep.get(key) for key in ("username", "firstName", "lastName", "email", "emailVerified", "requiredActions")}, REFERENCE["admin/user-after"])


if __name__ == "__main__":
    unittest.main()
