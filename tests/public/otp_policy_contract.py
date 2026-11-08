"""The realm OTP policy compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/otp-policy-observations.json:
the policy fields and their defaults, partial and full updates, the
CONFIGURE_TOTP page and its key URI under TOTP and HOTP policies, which
setup and login codes the look-ahead window and the HOTP counter accept,
a credential keeping its policy after the realm changes, and code reuse.
Credentials are compared by their OTP entry, since password hashing
parameters differ by design. Every recorded case is replayed; realms are
made once per class.
"""

import base64
import json
import pathlib
import re
import sys
import unittest

from login_case import LoginCase, reference

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
from otp_policy import FIELDS, REALMS  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import qr_code  # noqa: E402
from login_browser import base32, forms, hotp, totp  # noqa: E402

REFERENCE = reference("otp-policy-observations.json")
SETUP_CODES = {
    "sha256/now": ("sha256", lambda s: totp(s, 0, 8, 60, "HmacSHA256")),
    "sha256/previous-step": ("sha256", lambda s: totp(s, -1, 8, 60, "HmacSHA256")),
    "sha256/two-steps-ahead": ("sha256", lambda s: totp(s, 2, 8, 60, "HmacSHA256")),
    "sha256/six-digits": ("sha256", lambda s: totp(s, 0, 8, 60, "HmacSHA256")[2:]),
    "sha256/sha1-code": ("sha256", lambda s: totp(s, 0, 8, 60)),
    "sha512/now": ("sha512", lambda s: totp(s, 0, 6, 30, "HmacSHA512")),
    "sha512/previous-step": ("sha512", lambda s: totp(s, -1, 6, 30, "HmacSHA512")),
    "hotp/initial-counter": ("hotp", lambda s: hotp(s, 5)),
    "hotp/look-ahead-end": ("hotp", lambda s: hotp(s, 7)),
    "hotp/past-look-ahead": ("hotp", lambda s: hotp(s, 8)),
    "hotp/before-counter": ("hotp", lambda s: hotp(s, 4)),
}


class OtpPolicyCase(LoginCase):
    REALMS = REALMS

    def policy(self, key):
        _, realm = self.realm_admin(key, "")
        return {field: realm.get(field) for field in FIELDS}

    def setup_page(self, response):
        """As the recorder reduces it."""
        text = response[2].decode()
        result = self.shown(response)
        fields = next((form["fields"] for form in forms(response[2]) if "totpSecret" in form["fields"]), None)
        if fields is None:
            return result, None
        secret = fields["totpSecret"]
        encoded = base32(secret.encode())
        grouped = " ".join(encoded[i:i + 4] for i in range(0, len(encoded), 4))
        result["items"] = sorted(item.replace(grouped, "{key}") for item in result.get("items", []))
        image = re.search(r'<img[^>]*id="kc-totp-secret-qr-code"[^>]*src="data:image/png;base64,\s*([^"]+)"', text)
        if image:
            result["key_uri"] = self.normalized(qr_code.read(base64.b64decode(image.group(1)))["text"].replace(encoded, "{secret}"))
        return result, secret

    def set_up(self, key, username, code_of):
        self.new_user(key, username, {"requiredActions": ["CONFIGURE_TOTP"]})
        browser = self.browser(key)
        page = browser.sign_in(username, self.password)
        shown, secret = self.setup_page(page)
        return shown, self.shown(browser.submit(page, {"totp": code_of(secret), "userLabel": ""})), secret

    def code_form(self, key, username, code):
        browser = self.browser(key)
        page = browser.sign_in(username, self.password)
        return self.shown(browser.submit(page, {"otp": code}))


class RepresentationContract(OtpPolicyCase):
    def test_policies_and_updates(self):
        for key in ("default", "sha256", "hotp", "reusable", "untyped", "typed-alone"):
            self.assertEqual(self.policy(key), REFERENCE[f"representation/{key}"], key)
        for label, change in (
            ("partial-update", {"otpPolicyType": "totp", "otpPolicyDigits": 8}),
            ("update-without-type", {"otpPolicyDigits": 6}),
            ("full-update", {"otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 6, "otpPolicyPeriod": 30, "otpPolicyLookAheadWindow": 1, "otpPolicyInitialCounter": 0}),
        ):
            status, _ = self.realm_admin("partial", "", "PUT", change)
            self.assertEqual({"status": status} | self.policy("partial"), REFERENCE[label], label)


class SetupPageContract(OtpPolicyCase):
    def test_pages_under_each_policy(self):
        for key in ("default", "sha256", "sha512", "hotp"):
            self.new_user(key, "page-user", {"requiredActions": ["CONFIGURE_TOTP"]})
            browser = self.browser(key)
            page = browser.sign_in("page-user", self.password)
            self.assertEqual(self.setup_page(page)[0], REFERENCE[f"setup/{key}"], key)
            manual = browser.visit(re.search(r'<a href="([^"]*)" id="mode-manual"', page[2].decode()).group(1))
            self.assertEqual(self.setup_page(manual)[0], REFERENCE[f"setup-manual/{key}"], key)


def setup_code(label):
    def test(self):
        key, code_of = SETUP_CODES[label]
        _, result, _ = self.set_up(key, "setup-" + label.replace("/", "-"), code_of)
        self.assertEqual(result, REFERENCE[f"setup-code/{label}"])
    return test


class SetupCodeContract(OtpPolicyCase):
    pass


for name in SETUP_CODES:
    if name not in ("hotp/initial-counter", "hotp/look-ahead-end", "sha256/now"):
        setattr(SetupCodeContract, "test_" + name.replace("/", "_").replace("-", "_"), setup_code(name))


class LoginCodeContract(OtpPolicyCase):
    def test_hotp_counter(self):
        _, result, secret = self.set_up("hotp", "setup-hotp-initial-counter", lambda s: hotp(s, 5))
        self.assertEqual(result, REFERENCE["setup-code/hotp/initial-counter"])
        for label, counter in (("same-code", 5), ("next-counter", 6), ("skips-ahead", 9), ("behind", 8)):
            self.assertEqual(self.code_form("hotp", "setup-hotp-initial-counter", hotp(secret, counter)), REFERENCE[f"code/hotp/{label}"], label)

    def test_hotp_look_ahead_end(self):
        _, result, secret = self.set_up("hotp", "setup-hotp-look-ahead-end", lambda s: hotp(s, 7))
        self.assertEqual(result, REFERENCE["setup-code/hotp/look-ahead-end"])
        self.assertEqual(self.code_form("hotp", "setup-hotp-look-ahead-end", hotp(secret, 8)), REFERENCE["code/hotp/after-look-ahead-end"])

    def test_totp_window_after_setup(self):
        _, result, secret = self.set_up("sha256", "setup-sha256-now", lambda s: totp(s, 0, 8, 60, "HmacSHA256"))
        self.assertEqual(result, REFERENCE["setup-code/sha256/now"])
        self.assertEqual(self.code_form("sha256", "setup-sha256-now", totp(secret, 1, 8, 60, "HmacSHA256")), REFERENCE["code/sha256/now"])
        self.assertEqual(self.code_form("sha256", "setup-sha256-now", totp(secret, -1, 8, 60, "HmacSHA256")), REFERENCE["code/sha256/previous-step"])


class PolicyChangeContract(OtpPolicyCase):
    def test_credential_keeps_its_policy_and_reuse(self):
        _, result, secret = self.set_up("default", "kept-user", lambda s: totp(s))
        self.assertEqual(result, REFERENCE["setup-code/default/for-policy-change"])
        _, user = self.realm_admin("default", "/users?exact=true&username=kept-user")
        _, credentials = self.realm_admin("default", f"/users/{user[0]['id']}/credentials")
        otp = [("otp", credential.get("credentialData")) for credential in credentials if credential["type"] == "otp"]
        self.assertEqual([list(entry) for entry in otp], [entry for entry in REFERENCE["credential-data/default"] if entry[0] == "otp"])
        status, _ = self.realm_admin("default", "", "PUT", {"otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA256", "otpPolicyDigits": 8, "otpPolicyPeriod": 30, "otpPolicyLookAheadWindow": 1, "otpPolicyInitialCounter": 0})
        self.assertEqual(status, 204)
        self.assertEqual(self.code_form("default", "kept-user", totp(secret, 1)), REFERENCE["code/default/after-policy-change"])
        for key, digits, algorithm in (("default", 8, "HmacSHA256"), ("reusable", 6, "HmacSHA1")):
            username = "reuse-" + key
            _, result, secret = self.set_up(key, username, lambda s: totp(s, -1, digits, 30, algorithm))
            self.assertEqual(result, REFERENCE[f"setup-code/{key}/reuse"], key)
            code = totp(secret, 0, digits, 30, algorithm)
            self.assertEqual(self.code_form(key, username, code), REFERENCE[f"code/{key}/first-use"], key)
            self.assertEqual(self.code_form(key, username, code), REFERENCE[f"code/{key}/second-use"], key)


if __name__ == "__main__":
    unittest.main()
