"""Realm event settings compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/event-config-observations.json:
eventsEnabled, adminEventsEnabled and adminEventsDetailsEnabled in realm
representations, as the upstream test framework's events suppliers set
them, and GET and PUT /admin/realms/{realm}/events/config.

Known difference, listed in IMPLEMENTATION.md: event types are kept sorted
instead of in the reference's hash set order, which the recorder sorts too.
"""

import json
import pathlib
import unittest

from fixture import AdminCase

REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/event-config-observations.json").read_text()
)["observations"]

EVENT_FIELDS = ["eventsEnabled", "eventsExpiration", "eventsListeners", "enabledEventTypes", "adminEventsEnabled", "adminEventsDetailsEnabled"]


def realm_events(realm):
    events = {field: realm.get(field) for field in EVENT_FIELDS}
    if events["enabledEventTypes"] is not None:
        events["enabledEventTypes"] = sorted(events["enabledEventTypes"])
    return events


def config_summary(status, config):
    if status != 200:
        return {"status": status, "body": config}
    types = config.get("enabledEventTypes")
    return {
        "status": status,
        "fields": sorted(config),
        "settings": {field: config.get(field) for field in EVENT_FIELDS if field != "enabledEventTypes"},
        "enabled_event_types": sorted(types) if len(types) < 10 else {"count": len(types), "first": types[:6], "has_client_delete_error": "CLIENT_DELETE_ERROR" in types},
    }


class EventConfigContract(AdminCase):
    def admin(self, path, method="GET", payload=None, realm=None):
        status, _, body = self.call(method, f"/admin/realms/{realm or self.realm}{path}", payload)
        return status, json.loads(body) if body else None

    def test_defaults_and_creation(self):
        events = self.realm + "-events"
        self.addCleanup(self.call, "DELETE", "/admin/realms/" + events)
        payload = {"realm": events, "enabled": True, "eventsEnabled": True, "adminEventsEnabled": True, "adminEventsDetailsEnabled": True}
        self.assertEqual(self.call("POST", "/admin/realms", payload)[0], 201)
        for key, realm in (("plain", self.realm), ("events", events)):
            self.assertEqual(realm_events(self.admin("", realm=realm)[1]), REFERENCE[f"realm/{key}"], key)
            self.assertEqual(config_summary(*self.admin("/events/config", realm=realm)), REFERENCE[f"config/{key}"], key)
        self.assertEqual(self.admin("/events/config")[1]["enabledEventTypes"], REFERENCE["default-event-types"])

    def check_config_updates(self, cases):
        for label, payload in cases:
            status, body = self.admin("/events/config", "PUT", payload)
            self.assertEqual({"status": status, "body": body}, REFERENCE[f"put/{label}"], label)
            self.assertEqual(config_summary(*self.admin("/events/config")), REFERENCE[f"after/{label}"], label)
            self.assertEqual(realm_events(self.admin("")[1]), REFERENCE[f"realm-after/{label}"], label)

    def test_config_flags_and_types(self):
        self.check_config_updates([
            ("enable-all", {"eventsEnabled": True, "adminEventsEnabled": True, "adminEventsDetailsEnabled": True}),
            ("admin-flags-absent", {"eventsEnabled": True}),
            ("events-absent", {"adminEventsEnabled": True}),
            ("types", {"eventsEnabled": True, "enabledEventTypes": ["CLIENT_DELETE", "CLIENT_DELETE_ERROR"]}),
            ("types-empty", {"eventsEnabled": True, "enabledEventTypes": []}),
        ])

    def test_config_expiration_and_listeners(self):
        # The recorded sequence reaches these cases with every flag on.
        self.admin("/events/config", "PUT", {"eventsEnabled": True, "adminEventsEnabled": True, "adminEventsDetailsEnabled": True})
        cases = [
            ("expiration", {"eventsEnabled": True, "eventsExpiration": 3600}),
            ("expiration-absent", {"eventsEnabled": True}),
            ("listeners-empty", {"eventsEnabled": True, "eventsListeners": []}),
            ("listeners-default", {"eventsEnabled": True, "eventsListeners": ["jboss-logging"]}),
            ("listeners-unknown", {"eventsEnabled": True, "eventsListeners": ["no-such-listener"]}),
            ("not-an-object", []),
        ]
        self.check_config_updates(cases)

    def test_realm_updates_and_access(self):
        self.admin("/events/config", "PUT", {"eventsEnabled": True, "adminEventsEnabled": True, "adminEventsDetailsEnabled": True})
        cases = [
            ("flags", {"eventsEnabled": False, "adminEventsEnabled": True, "adminEventsDetailsEnabled": False}),
            ("flags-absent", {"displayName": "Events"}),
            ("types", {"enabledEventTypes": ["LOGIN_ERROR"]}),
            ("types-empty", {"enabledEventTypes": []}),
            ("expiration", {"eventsExpiration": 60}),
            ("wrong-type", {"eventsEnabled": "yes"}),
        ]
        for label, payload in cases:
            status, body = self.admin("", "PUT", payload)
            self.assertEqual({"status": status, "body": body}, REFERENCE[f"realm-put/{label}"], label)
            self.assertEqual(realm_events(self.admin("")[1]), REFERENCE[f"realm-put-after/{label}"], label)
        status = self.call("GET", f"/admin/realms/{self.realm}/events/config", token=False)[0]
        self.assertEqual({"status": status}, REFERENCE["config/no-token"])
        self.assertEqual({"status": self.admin("/events/config/missing")[0]}, REFERENCE["config/unknown-path"])


if __name__ == "__main__":
    unittest.main()
