"""The realm OTP policy compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/otp-policy-observations.json:
the policy fields and their defaults, partial and full updates, and the
CONFIGURE_TOTP manual mode with the policy and supported apps under TOTP
and HOTP policies. The key URIs and code checks are in
otp_codes_contract.py. Every recorded case is replayed; realms are made
once per class.
"""

import pathlib
import re
import sys
import unittest

from login_case import reference
from otp_codes_contract import OtpCase

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
from otp_policy import FIELDS, REALMS  # noqa: E402

REFERENCE = reference("otp-policy-observations.json")


class OtpPolicyCase(OtpCase):
    REALMS = REALMS

    def policy(self, key):
        _, realm = self.realm_admin(key, "")
        return {field: realm.get(field) for field in FIELDS}


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


def manual_page(key):
    def test(self):
        self.new_user(key, "page-user", {"requiredActions": ["CONFIGURE_TOTP"]})
        browser = self.browser(key)
        page = browser.sign_in("page-user", self.password)
        manual = browser.visit(re.search(r'<a href="([^"]*)" id="mode-manual"', page[2].decode()).group(1))
        self.assertEqual(self.setup_page(manual)[0], REFERENCE[f"setup-manual/{key}"])
    return test


class ManualSetupContract(OtpPolicyCase):
    pass


for name in ("default", "sha256", "sha512", "hotp"):
    setattr(ManualSetupContract, "test_" + name, manual_page(name))


if __name__ == "__main__":
    unittest.main()
