"""VERIFY_PROFILE compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/verify-profile-observations.json:
the action's default setting, signing in users missing required profile
fields with the action on and off, the form's field errors, failed and
passing submissions with the stored profile, the username with
editUsernameAllowed, and a user who also has UPDATE_PROFILE. Every
recorded case is replayed; realms are made once per class.
"""

import unittest

from login_case import LoginCase, reference

REFERENCE = reference("verify-profile-observations.json")
CASES = {
    "complete": {},
    "no-first-name": {"firstName": None},
    "no-last-name-email": {"lastName": None, "email": None},
    "nothing": {"firstName": None, "lastName": None, "email": None},
}


class VerifyProfileCase(LoginCase):
    REALMS = {"default": {}, "off": {}, "edit": {"editUsernameAllowed": True}}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.users = {}
        for label, missing in CASES.items():
            for key in ("default", "off"):
                cls.users[label, key] = cls.new_user(key, f"{label}-{key}", missing)
        cls.new_user("edit", "edit-user", {"firstName": None})
        cls.new_user("edit", "taken-user")
        cls.new_user("default", "both-user", {"firstName": None, "requiredActions": ["UPDATE_PROFILE"]})

    def stored(self, key, user_id):
        _, user = self.realm_admin(key, f"/users/{user_id}")
        return user


class ActionContract(VerifyProfileCase):
    def test_default_setting_and_turning_off(self):
        status, action = self.realm_admin("off", "/authentication/required-actions/VERIFY_PROFILE")
        self.assertEqual({"status": status, "enabled": action["enabled"], "defaultAction": action["defaultAction"], "priority": action["priority"]}, REFERENCE["action/default"])
        status, _ = self.realm_admin("off", "/authentication/required-actions/VERIFY_PROFILE", "PUT", action | {"enabled": False})
        self.assertEqual({"status": status}, REFERENCE["action/turned-off"])
        for label in CASES:
            browser = self.browser("off")
            self.assertEqual(self.shown(browser.sign_in(f"{label}-off", self.password)), REFERENCE[f"sign-in/{label}/off"], label)
            self.assertEqual({"requiredActions": self.stored("off", self.users[label, "off"])["requiredActions"]}, REFERENCE[f"user-while-pending/{label}/off"])


def replay(label):
    def test(self):
        user_id = self.users[label, "default"]
        browser = self.browser("default")
        page = browser.sign_in(f"{label}-default", self.password)
        self.assertEqual(self.shown(page), REFERENCE[f"sign-in/{label}/default"])
        self.assertEqual({"requiredActions": self.stored("default", user_id)["requiredActions"]}, REFERENCE[f"user-while-pending/{label}/default"])
        if label == "complete":
            return
        page = browser.submit(page, {"firstName": "", "lastName": "", "email": ""})
        self.assertEqual(self.shown(page), REFERENCE[f"empty-post/{label}"])
        page = browser.submit(page, {"firstName": "Given", "lastName": "Family", "email": "not-an-email"})
        self.assertEqual(self.shown(page), REFERENCE[f"bad-email/{label}"])
        self.assertEqual(self.shown(browser.submit(page, {"firstName": "Given", "lastName": "Family", "email": f"new-{label}@example.invalid"})), REFERENCE[f"passing/{label}"])
        stored = self.stored("default", user_id)
        self.assertEqual({field: stored.get(field) for field in ("firstName", "lastName", "email", "emailVerified", "requiredActions")}, REFERENCE[f"user-after/{label}"])
        self.assertEqual(self.shown(self.browser("default").sign_in(f"{label}-default", self.password)), REFERENCE[f"sign-in-again/{label}"])
    return test


class SignInContract(VerifyProfileCase):
    pass


for name in CASES:
    setattr(SignInContract, "test_" + name.replace("-", "_"), replay(name))


class FormContract(VerifyProfileCase):
    def test_username_with_edit_allowed(self):
        browser = self.browser("edit")
        page = browser.sign_in("edit-user", self.password)
        self.assertEqual(self.shown(page), REFERENCE["sign-in/edit"])
        page = browser.submit(page, {"username": "taken-user", "firstName": "Given", "lastName": "Family"})
        self.assertEqual(self.shown(page), REFERENCE["taken-username/edit"])
        self.assertEqual(self.shown(browser.submit(page, {"username": "renamed-user", "firstName": "Given", "lastName": "Family"})), REFERENCE["renamed/edit"])

    def test_with_update_profile(self):
        browser = self.browser("default")
        page = browser.sign_in("both-user", self.password)
        self.assertEqual(self.shown(page), REFERENCE["sign-in/update-profile-too"])
        self.assertEqual(self.shown(browser.submit(page, {"firstName": "Given", "lastName": "Family"})), REFERENCE["passing/update-profile-too"])


if __name__ == "__main__":
    unittest.main()
