"""Stored login events compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/login-event-observations.json:
LOGIN and LOGIN_ERROR from the login form, and GET and DELETE
/admin/realms/{realm}/events with each filter. The sign-ins run once per
class, so each test lists events.
"""

import datetime
import time
import unittest
import urllib.parse

from login_case import LoginCase, reference

REFERENCE = reference("login-event-observations.json")
SHOWN_DETAILS = ["auth_method", "auth_type", "response_type", "redirect_uri", "consent", "username", "response_mode"]


class LoginEventsContract(LoginCase):
    REALMS = {
        "events": {"eventsEnabled": True},
        "off": {},
        "types": {"eventsEnabled": True, "enabledEventTypes": ["LOGIN"]},
        "expiry": {"eventsEnabled": True, "eventsExpiration": 1},
        "cleared": {"eventsEnabled": True},
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.users = {key: cls.new_user(key, "alice") for key in cls.REALMS}
        cls.started = int(time.time() * 1000)
        for key in cls.REALMS:
            cls.browser(cls, key).sign_in("nobody", "wrong")
            cls.browser(cls, key).sign_in("alice", "wrong")
            status, headers, _ = cls.browser(cls, key).sign_in("alice", cls.password)
            assert status == 302 and "/callback?" in headers["location"], key
        cls.finished = int(time.time() * 1000)
        # Past the one-second expiration, with no event written since.
        time.sleep(1.1)

    def events(self, key, query=""):
        return self.realm_admin(key, "/events" + ("?" + query if query else ""))

    def summary(self, event, user_id):
        details = event.get("details", {})
        return {
            "fields": sorted(event),
            "type": event["type"],
            "error": event.get("error"),
            "client": event.get("clientId"),
            "user_is_fixture": event.get("userId") == user_id if "userId" in event else None,
            "ip_address": event.get("ipAddress"),
            "detail_keys": sorted(details),
            "details": self.normalized({key: details[key] for key in SHOWN_DETAILS if key in details}),
            "code_id_is_session": details.get("code_id") == event["sessionId"] if "sessionId" in event else None,
            "time_is_millis": event["time"] > 10 ** 12,
        }

    def test_listing(self):
        status, events = self.events("events")
        self.assertEqual({"status": status, "events": [self.summary(event, self.users["events"]) for event in events]}, REFERENCE["list/default"])
        status, events = self.events("events", "direction=asc")
        observed = {"status": status, "types": [event["type"] for event in events], "errors": [event.get("error") for event in events]}
        self.assertEqual(observed, REFERENCE["list/asc"])
        for key in ("off", "types"):
            status, events = self.events(key, "direction=asc")
            self.assertEqual({"status": status, "types": [event["type"] for event in events]}, REFERENCE[f"list/{key}"], key)
        status, events = self.events("expiry")
        self.assertEqual({"status": status, "types": [event["type"] for event in events]}, REFERENCE["list/expired"])

    def test_filters(self):
        today = datetime.datetime.now(datetime.UTC).date()
        cases = {
            "type-login-error": "type=LOGIN_ERROR",
            "type-two": "type=LOGIN&type=LOGIN_ERROR",
            "client": "client=login-app",
            "client-other": "client=other-app",
            "user": "user=" + self.users["events"],
            "ip": "ipAddress=127.0.0.1",
            "max": "max=1",
            "first": "first=1&max=1",
            "first-only": "first=2",
            "epoch-range": f"dateFrom={self.started}&dateTo={self.finished}",
            "epoch-before": f"dateTo={self.started - 1}",
            "date-today": f"dateFrom={today}&dateTo={today}",
            "date-past": f"dateTo={today - datetime.timedelta(days=2)}",
            "date-invalid": "dateFrom=yesterday",
            "direction-invalid": "direction=sideways",
        }
        for label, query in cases.items():
            status, events = self.events("events", query)
            observed = {"status": status, "types": [event["type"] for event in events] if isinstance(events, list) else events}
            self.assertEqual(observed, REFERENCE[f"filter/{label}"], label)

    def test_clear_and_access(self):
        name = self.names["types"]
        self.assertEqual({"status": self.request("GET", f"/admin/realms/{name}/events")[0]}, REFERENCE["list/no-token"])
        self.assertEqual({"status": self.request("DELETE", f"/admin/realms/{name}/events")[0]}, REFERENCE["clear/no-token"])
        status = self.admin("GET", "/admin/realms/no-such-realm-" + urllib.parse.quote(name) + "/events")[0]
        self.assertEqual({"status": status}, REFERENCE["list/unknown-realm"])
        # A realm of its own, since the listing tests read the others.
        self.assertEqual(len(self.events("cleared")[1]), 3)
        status, body = self.realm_admin("cleared", "/events", "DELETE")
        self.assertEqual({"status": status, "body": body}, REFERENCE["clear"])
        status, events = self.events("cleared")
        self.assertEqual({"status": status, "events": events}, REFERENCE["list/cleared"])


if __name__ == "__main__":
    unittest.main()
