"""TOTP setup key URIs and OTP code checks compared with recorded Keycloak
26.8.1 behavior.

Expected cases come from tests/reference/otp-code-observations.json: the
key URI the CONFIGURE_TOTP page's QR code holds under TOTP and HOTP
policies, which setup and login codes the look-ahead window and the HOTP
counter accept, a credential keeping its policy after the realm changes,
and code reuse. Credentials are compared by their OTP entry, since
password hashing parameters differ by design. Every recorded case is
replayed; realms are made once per class, and numbered tests replay one
credential's recorded sequence in order.
"""

import base64
import pathlib
import re
import sys
import unittest

from login_case import LoginCase, reference

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
from otp_codes import REALMS, SETUP_CODES  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import qr_code  # noqa: E402
from login_browser import base32, forms, hotp, totp  # noqa: E402

REFERENCE = reference("otp-code-observations.json")


class OtpCase(LoginCase):
    """Setup pages and code forms, reduced as the recorders reduce them."""

    REALMS = REALMS

    def setup_page(self, response):
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


def key_uri(key):
    def test(self):
        self.new_user(key, "page-user", {"requiredActions": ["CONFIGURE_TOTP"]})
        browser = self.browser(key)
        self.assertEqual(self.setup_page(browser.sign_in("page-user", self.password))[0], REFERENCE[f"setup/{key}"])
    return test


class KeyUriContract(OtpCase):
    pass


for name in ("default", "sha256", "sha512", "hotp"):
    setattr(KeyUriContract, "test_" + name, key_uri(name))


def setup_code(label):
    def test(self):
        key, code_of = SETUP_CODES[label]
        _, result, _ = self.set_up(key, "setup-" + label.replace("/", "-"), code_of)
        self.assertEqual(result, REFERENCE[f"setup-code/{label}"])
    return test


class SetupCodeContract(OtpCase):
    pass


for name in SETUP_CODES:
    if name not in ("hotp/initial-counter", "hotp/look-ahead-end", "sha256/now"):
        setattr(SetupCodeContract, "test_" + name.replace("/", "_").replace("-", "_"), setup_code(name))


class HotpCounterContract(OtpCase):
    """The numbered tests replay one credential's recorded counter in order."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.new_user("hotp", "setup-hotp-initial-counter", {"requiredActions": ["CONFIGURE_TOTP"]})

    def test_1_setup(self):
        browser = self.browser("hotp")
        page = browser.sign_in("setup-hotp-initial-counter", self.password)
        type(self).secret = self.setup_page(page)[1]
        result = self.shown(browser.submit(page, {"totp": hotp(self.secret, 5), "userLabel": ""}))
        self.assertEqual(result, REFERENCE["setup-code/hotp/initial-counter"])

    def test_2_used_and_next(self):
        for label, counter in (("same-code", 5), ("next-counter", 6)):
            self.assertEqual(self.code_form("hotp", "setup-hotp-initial-counter", hotp(self.secret, counter)), REFERENCE[f"code/hotp/{label}"], label)

    def test_3_ahead_and_behind(self):
        for label, counter in (("skips-ahead", 9), ("behind", 8)):
            self.assertEqual(self.code_form("hotp", "setup-hotp-initial-counter", hotp(self.secret, counter)), REFERENCE[f"code/hotp/{label}"], label)


class LoginCodeContract(OtpCase):
    def test_hotp_look_ahead_end(self):
        _, result, secret = self.set_up("hotp", "setup-hotp-look-ahead-end", lambda s: hotp(s, 7))
        self.assertEqual(result, REFERENCE["setup-code/hotp/look-ahead-end"])
        self.assertEqual(self.code_form("hotp", "setup-hotp-look-ahead-end", hotp(secret, 8)), REFERENCE["code/hotp/after-look-ahead-end"])

    def test_totp_window_after_setup(self):
        _, result, secret = self.set_up("sha256", "setup-sha256-now", lambda s: totp(s, 0, 8, 60, "HmacSHA256"))
        self.assertEqual(result, REFERENCE["setup-code/sha256/now"])
        self.assertEqual(self.code_form("sha256", "setup-sha256-now", totp(secret, 1, 8, 60, "HmacSHA256")), REFERENCE["code/sha256/now"])
        self.assertEqual(self.code_form("sha256", "setup-sha256-now", totp(secret, -1, 8, 60, "HmacSHA256")), REFERENCE["code/sha256/previous-step"])


class PolicyChangeContract(OtpCase):
    """The numbered tests run in order: the policy change of the first
    sets the default realm's policy for the second."""

    def test_1_credential_keeps_its_policy(self):
        _, result, secret = self.set_up("default", "kept-user", lambda s: totp(s))
        self.assertEqual(result, REFERENCE["setup-code/default/for-policy-change"])
        _, user = self.realm_admin("default", "/users?exact=true&username=kept-user")
        _, credentials = self.realm_admin("default", f"/users/{user[0]['id']}/credentials")
        otp = [("otp", credential.get("credentialData")) for credential in credentials if credential["type"] == "otp"]
        self.assertEqual([list(entry) for entry in otp], [entry for entry in REFERENCE["credential-data/default"] if entry[0] == "otp"])
        status, _ = self.realm_admin("default", "", "PUT", {"otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA256", "otpPolicyDigits": 8, "otpPolicyPeriod": 30, "otpPolicyLookAheadWindow": 1, "otpPolicyInitialCounter": 0})
        self.assertEqual(status, 204)
        self.assertEqual(self.code_form("default", "kept-user", totp(secret, 1)), REFERENCE["code/default/after-policy-change"])

    # The default realm's policy is now HmacSHA256 with 8 digits.
    REUSE = {"default": (8, "HmacSHA256"), "reusable": (6, "HmacSHA1")}
    codes = {}

    def first_use(self, key):
        digits, algorithm = self.REUSE[key]
        username = "reuse-" + key
        _, result, secret = self.set_up(key, username, lambda s: totp(s, -1, digits, 30, algorithm))
        self.assertEqual(result, REFERENCE[f"setup-code/{key}/reuse"])
        code = totp(secret, 0, digits, 30, algorithm)
        self.codes[key] = code
        self.assertEqual(self.code_form(key, username, code), REFERENCE[f"code/{key}/first-use"])

    def second_use(self, key):
        self.assertEqual(self.code_form(key, "reuse-" + key, self.codes[key]), REFERENCE[f"code/{key}/second-use"])

    def test_2_default_code_first_use(self):
        self.first_use("default")

    def test_3_default_code_used_again(self):
        self.second_use("default")

    def test_4_reusable_code_first_use(self):
        self.first_use("reusable")

    def test_5_reusable_code_used_again(self):
        self.second_use("reusable")


if __name__ == "__main__":
    unittest.main()
