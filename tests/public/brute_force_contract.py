"""Brute-force detection compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/brute-force-observations.json:
the realm settings and defaults, a realm without detection that never
locks, failure counts and the temporary lockout after failureFactor
failures, the quick-login lockout, permanent lockout disabling the user
until an admin enables them, and the attack-detection endpoints. Every
recorded case is replayed; realms are made once per class.
"""

import pathlib
import sys
import unittest

from login_case import LoginCase, reference

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
from brute_force import FIELDS, REALMS  # noqa: E402

REFERENCE = reference("brute-force-observations.json")
UNKNOWN_ID = "00000000-0000-0000-0000-000000000000"


class BruteForceCase(LoginCase):
    REALMS = REALMS

    def attempt(self, key, username, password):
        return self.shown(self.browser(key).sign_in(username, password))

    def status_of(self, key, user_id):
        """As the recorder reduces it; this server counts failures before it
        answers, so nothing waits."""
        status, found = self.realm_admin(key, f"/attack-detection/brute-force/users/{user_id}")
        if not isinstance(found, dict):
            return {"status": status}
        result = {"status": status} | {field: found.get(field) for field in ("disabled", "numFailures", "numTemporaryLockouts", "numSecondaryAuthFailures")}
        result["lastFailure"] = found.get("lastFailure", 0) > 0
        result["lastIPFailure"] = found.get("lastIPFailure") if found.get("lastIPFailure") == "n/a" else "ip"
        result["locked_until"] = "none" if not found.get("failedLoginNotBefore") else "permanent" if found["failedLoginNotBefore"] >= 2 ** 63 - 1 else "later"
        result["fields"] = sorted(found)
        return result


class SettingsContract(BruteForceCase):
    def test_representation(self):
        for key in ("off", "protected"):
            _, realm = self.realm_admin(key, "")
            self.assertEqual({field: realm.get(field) for field in FIELDS}, REFERENCE[f"representation/{key}"], key)


class UnprotectedContract(BruteForceCase):
    """The numbered tests replay one user's recorded sequence in order."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.user = cls.new_user("off", "off-user")

    def test_1_wrong_passwords(self):
        for number in range(6):
            self.assertEqual(self.attempt("off", "off-user", "wrong"), REFERENCE[f"off/wrong-{number}"], number)

    def test_2_never_locks(self):
        self.assertEqual(self.attempt("off", "off-user", self.password), REFERENCE["off/right"])
        self.assertEqual(self.status_of("off", self.user), REFERENCE["off/status"])


class TemporaryLockoutContract(BruteForceCase):
    """The numbered tests replay one user's recorded sequence in order."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.locked = cls.new_user("protected", "locked-user")

    def test_1_lockout(self):
        user = self.locked
        self.assertEqual(self.status_of("protected", user), REFERENCE["protected/status-before"])
        for number in (1, 2):
            self.assertEqual(self.attempt("protected", "locked-user", "wrong"), REFERENCE[f"protected/wrong-{number}"])
            self.assertEqual(self.status_of("protected", user), REFERENCE[f"protected/status-{number}"])
        self.assertEqual(self.attempt("protected", "locked-user", self.password), REFERENCE["protected/right-while-locked"])
        self.assertEqual(self.status_of("protected", user), REFERENCE["protected/status-after-right"])
        _, stored = self.realm_admin("protected", f"/users/{user}")
        self.assertEqual(stored["enabled"], REFERENCE["protected/user-enabled"])

    def test_2_clearing(self):
        user = self.locked
        status, _ = self.realm_admin("protected", f"/attack-detection/brute-force/users/{user}", "DELETE")
        self.assertEqual({"status": status, "after": self.status_of("protected", user)}, REFERENCE["protected/clear-user"])
        self.assertEqual(self.attempt("protected", "locked-user", self.password), REFERENCE["protected/right-after-clear"])
        self.assertEqual(self.attempt("protected", "locked-user", "wrong"), REFERENCE["protected/wrong-after-success"])
        self.assertEqual(self.attempt("protected", "locked-user", self.password), REFERENCE["protected/right-after-one"])
        self.assertEqual(self.status_of("protected", user), REFERENCE["protected/status-after-success"])

    def test_unknown_users_and_clearing_all(self):
        self.assertEqual(self.attempt("protected", "nobody", "wrong"), REFERENCE["protected/unknown-user"])
        self.assertEqual(self.status_of("protected", UNKNOWN_ID), REFERENCE["protected/status-unknown-id"])
        other = self.new_user("protected", "other-user")
        self.attempt("protected", "other-user", "wrong")
        self.attempt("protected", "other-user", "wrong")
        status, _ = self.realm_admin("protected", "/attack-detection/brute-force/users", "DELETE")
        self.assertEqual({"status": status, "after": self.status_of("protected", other)}, REFERENCE["protected/clear-all"])
        self.assertEqual(self.attempt("protected", "other-user", self.password), REFERENCE["protected/right-after-clear-all"])


class QuickAndPermanentContract(BruteForceCase):
    def test_quick_login_lockout(self):
        user = self.new_user("quick", "quick-user")
        self.assertEqual(self.attempt("quick", "quick-user", "wrong"), REFERENCE["quick/wrong-1"])
        self.assertEqual(self.attempt("quick", "quick-user", "wrong"), REFERENCE["quick/wrong-2"])
        self.assertEqual(self.status_of("quick", user), REFERENCE["quick/status"])
        self.assertEqual(self.attempt("quick", "quick-user", self.password), REFERENCE["quick/right-while-locked"])

    def test_permanent_lockout(self):
        user = self.new_user("permanent", "permanent-user")
        self.assertEqual(self.attempt("permanent", "permanent-user", "wrong"), REFERENCE["permanent/wrong-1"])
        self.assertEqual(self.attempt("permanent", "permanent-user", "wrong"), REFERENCE["permanent/wrong-2"])
        self.assertEqual(self.status_of("permanent", user), REFERENCE["permanent/status"])
        _, stored = self.realm_admin("permanent", f"/users/{user}")
        self.assertEqual({"enabled": stored["enabled"], "attributes": stored.get("attributes")}, REFERENCE["permanent/user"])
        self.assertEqual(self.attempt("permanent", "permanent-user", self.password), REFERENCE["permanent/right"])
        status, _ = self.realm_admin("permanent", f"/users/{user}", "PUT", {"enabled": True})
        self.assertEqual({"status": status, "after": self.status_of("permanent", user)}, REFERENCE["permanent/enabled-again"])
        self.assertEqual(self.attempt("permanent", "permanent-user", self.password), REFERENCE["permanent/right-after-enable"])


if __name__ == "__main__":
    unittest.main()
