"""Stored admin events compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/admin-event-observations.json:
the events user, client, role, group and realm changes record, the events
config rules, realm creation and deletion in the master realm, and GET and
DELETE /admin/realms/{realm}/admin-events with each filter.

Known differences, listed in IMPLEMENTATION.md: a representation is the
request body, so the fields the reference's resources add to it (`id`,
`composite`, `subGroups`) are not compared, a DELETE keeps none, and a
created realm's representation is compared only for being kept.
"""

import datetime
import json
import secrets
import time
import unittest

from fixture import AdminCase, ENDPOINT

REFERENCE = json.loads(
    (__import__("pathlib").Path(__file__).resolve().parents[1] / "reference/admin-event-observations.json").read_text()
)["observations"]

ADDED_BY_REFERENCE = {"id", "composite", "subGroups"}


def comparable(summary):
    """A recorded event summary as this server can match it."""
    summary = dict(summary)
    shown = summary["representation"]
    if summary["operation"] == "DELETE":
        summary["representation"] = None
        summary["fields"] = [field for field in summary["fields"] if field != "representation"]
    elif shown is not None and summary["resource_type"] == "REALM" and summary["resource_path"] and summary["resource_path"].startswith("{realm-"):
        summary["representation"] = "kept"
    elif shown is not None and "fields" in shown:
        summary["representation"] = dict(shown, fields=[field for field in shown["fields"] if field not in ADDED_BY_REFERENCE])
    return summary


class AdminEventsContract(AdminCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        status, _, body = cls.request("POST", ENDPOINT + "/token", form={"grant_type": "client_credentials", "client_id": cls.ADMIN, "client_secret": cls.ADMIN_SECRET})
        assert status == 200
        cls.token = json.loads(body)["access_token"]
        cls.master_id = cls.get("/admin/realms/master")["id"]
        cls.admin_client = cls.get(f"/admin/realms/master/clients?clientId={cls.ADMIN}")[0]["id"]
        cls.service_account = cls.get(f"/admin/realms/master/clients/{cls.admin_client}/service-account-user")["id"]

    @classmethod
    def send(cls, method, path, payload=None):
        headers = {"Authorization": "Bearer " + cls.token}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload)
        status, response_headers, data = cls.request(method, path, headers, body=body)
        return status, response_headers, json.loads(data) if data else None

    @classmethod
    def get(cls, path):
        return cls.send("GET", path)[2]

    def setUp(self):
        super().setUp()
        self.names = {key: f"{self.realm}-{key}" for key in ("admin", "details", "off", "config", "created")}
        self.realm_ids = {}
        self.ids = {}

    def make_realms(self, settings):
        for key, extra in settings.items():
            self.assertEqual(self.send("POST", "/admin/realms", {"realm": self.names[key], "enabled": True} | extra)[0], 201)
            self.addCleanup(self.send, "DELETE", "/admin/realms/" + self.names[key])
            self.realm_ids[key] = self.get("/admin/realms/" + self.names[key])["id"]

    def normalized(self, text):
        for label, value in sorted(self.ids.items(), key=lambda item: -len(item[1])):
            text = text.replace(value, "{" + label + "}")
        for key in sorted(self.names, key=lambda item: -len(self.names[item])):
            text = text.replace(self.names[key], "{realm-" + key + "}")
        return text

    def summary(self, event, key):
        auth = event.get("authDetails", {})
        representation = event.get("representation")
        parsed = json.loads(representation) if representation else None
        shown = None
        if isinstance(parsed, dict):
            shown = {"fields": sorted(parsed), "secret": parsed.get("secret"), "username": parsed.get("username")}
        return {
            "fields": sorted(event),
            "operation": event["operationType"],
            "resource_type": event.get("resourceType"),
            "resource_path": self.normalized(event["resourcePath"]) if "resourcePath" in event else None,
            "realm_is_own": event.get("realmId") == self.realm_ids.get(key),
            "auth_fields": sorted(auth),
            "auth_realm_is_master": auth.get("realmId") == self.master_id,
            "auth_client_is_bootstrap": auth.get("clientId") == self.admin_client,
            "auth_user_is_service_account": auth.get("userId") == self.service_account,
            "auth_ip": auth.get("ipAddress"),
            "representation": shown,
            "time_is_millis": event["time"] > 10 ** 12,
        }

    def events(self, key, query="direction=asc"):
        status, _, listed = self.send("GET", f"/admin/realms/{self.names[key]}/admin-events?{query}")
        return status, listed

    def changes(self, key):
        """The recorder's changes in one realm."""
        name = self.names[key]
        base = f"/admin/realms/{name}"
        status, headers, _ = self.send("POST", base + "/users", {"username": "alice", "enabled": True, "firstName": "Reference", "lastName": "User", "email": "alice@example.invalid", "emailVerified": True, "credentials": [{"type": "password", "value": secrets.token_urlsafe(20), "temporary": False}]})
        self.assertEqual(status, 201)
        user = headers["location"].rsplit("/", 1)[1]
        self.ids["user"] = user
        self.send("PUT", f"{base}/users/{user}", {"firstName": "Changed"})
        self.send("PUT", f"{base}/users/{user}/reset-password", {"type": "password", "value": secrets.token_urlsafe(20), "temporary": False})
        status, headers, _ = self.send("POST", base + "/clients", {"clientId": "events-app", "secret": "client-secret-value-" + secrets.token_hex(12), "protocolMappers": [{"name": "audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": {"included.custom.audience": "events-app", "access.token.claim": "true"}}]})
        self.assertEqual(status, 201)
        self.ids["client"] = headers["location"].rsplit("/", 1)[1]
        self.assertEqual(self.send("POST", base + "/roles", {"name": "events-role"})[0], 201)
        status, headers, _ = self.send("POST", base + "/groups", {"name": "events-group"})
        self.assertEqual(status, 201)
        self.ids["group"] = headers["location"].rsplit("/", 1)[1]
        self.send("PUT", base, {"displayName": "Fury Road"})
        duplicate = self.send("POST", base + "/users", {"username": "alice"})[0]
        self.send("DELETE", f"{base}/users/{user}")
        return duplicate

    def test_changes_by_setting(self):
        self.make_realms({"admin": {"adminEventsEnabled": True}, "details": {"adminEventsEnabled": True, "adminEventsDetailsEnabled": True}, "off": {}})
        for key in ("admin", "details", "off"):
            self.assertEqual({"events": len(self.events(key)[1])}, REFERENCE[f"initial/{key}"], key)
            duplicate = self.changes(key)
            status, listed = self.events(key)
            expected = REFERENCE[f"events/{key}"]
            expected = dict(expected, events=[comparable(event) for event in expected["events"]])
            observed = {"status": status, "duplicate_status": duplicate, "events": [comparable(self.summary(event, key)) for event in listed]}
            self.assertEqual(observed, expected, key)

    def test_filters_and_clearing(self):
        self.make_realms({"admin": {"adminEventsEnabled": True}})
        self.changes("admin")
        status, listed = self.events("admin", "direction=desc")
        self.assertEqual({"status": self.events("admin", "")[0], "same_as_desc": self.events("admin", "")[1] == listed}, REFERENCE["order/default"])
        today = datetime.datetime.now(datetime.UTC).date()
        cases = {
            "operation-create": "operationTypes=CREATE&direction=asc",
            "operation-two": "operationTypes=CREATE&operationTypes=DELETE&direction=asc",
            "resource-user": "resourceTypes=USER&direction=asc",
            "path-users": "resourcePath=users/*&direction=asc",
            # The recorder's id is a user of another realm.
            "path-exact": f"resourcePath=users/{secrets.token_hex(8)}&direction=asc",
            "auth-realm": f"authRealm={self.master_id}&direction=asc",
            "auth-realm-other": f"authRealm={self.realm_ids['admin']}&direction=asc",
            "auth-client": f"authClient={self.admin_client}&direction=asc",
            "auth-user": f"authUser={self.service_account}&direction=asc",
            "auth-ip": "authIpAddress=127.0.0.1&direction=asc",
            "max": "max=2&direction=asc",
            "first": "first=2&max=2&direction=asc",
            "date-today": f"dateFrom={today}&dateTo={today}&direction=asc",
            "epoch-future": f"dateFrom={int(time.time() * 1000) + 3600000}",
            "date-invalid": "dateTo=tomorrow",
            "direction-invalid": "direction=up",
        }
        for label, query in cases.items():
            status, listed = self.events("admin", query)
            operations = [[event["operationType"], event.get("resourceType")] for event in listed] if isinstance(listed, list) else listed
            self.assertEqual({"status": status, "operations": operations}, REFERENCE[f"filter/{label}"], label)
        status, _, body = self.send("DELETE", f"/admin/realms/{self.names['admin']}/admin-events")
        self.assertEqual({"status": status, "body": body, "after": self.events("admin")[1]}, REFERENCE["clear"])
        name = self.names["admin"]
        self.assertEqual({"status": self.request("GET", f"/admin/realms/{name}/admin-events")[0]}, REFERENCE["list/no-token"])
        self.assertEqual({"status": self.request("DELETE", f"/admin/realms/{name}/admin-events")[0]}, REFERENCE["clear/no-token"])

    def test_events_config(self):
        self.make_realms({"config": {}})
        base = f"/admin/realms/{self.names['config']}"
        cases = [
            ("off-to-on", {"adminEventsEnabled": True, "adminEventsDetailsEnabled": True}),
            ("on-to-on", {"eventsEnabled": True, "adminEventsEnabled": True, "adminEventsDetailsEnabled": True}),
            ("on-to-off", {"eventsEnabled": True, "adminEventsEnabled": False, "adminEventsDetailsEnabled": True}),
            ("off-to-off", {"eventsEnabled": True, "adminEventsEnabled": False, "adminEventsDetailsEnabled": False}),
        ]
        for label, payload in cases:
            status = self.send("PUT", base + "/events/config", payload)[0]
            observed = {"status": status, "events": [self.summary(event, "config") for event in self.events("config")[1]]}
            self.assertEqual(observed, REFERENCE[f"config/{label}"], label)
        self.send("PUT", base, {"adminEventsEnabled": True})
        self.assertEqual({"events": len(self.events("config")[1])}, REFERENCE["realm-update-enabling"])
        self.send("PUT", base, {"adminEventsEnabled": False})
        observed = {"events": [self.summary(event, "config") for event in self.events("config")[1]][3:]}
        self.assertEqual(observed, REFERENCE["realm-update-disabling"])

    def test_realm_creation_in_master(self):
        config = self.get("/admin/realms/master/events/config")
        self.addCleanup(self.send, "PUT", "/admin/realms/master/events/config", config)
        self.send("PUT", "/admin/realms/master/events/config", config | {"adminEventsEnabled": True, "adminEventsDetailsEnabled": True})
        started = int(time.time() * 1000)
        created = self.names["created"]
        self.assertEqual(self.send("POST", "/admin/realms", {"realm": created, "id": created, "enabled": True})[0], 201)
        self.assertEqual(self.send("DELETE", "/admin/realms/" + created)[0], 204)
        # Other contract files share the master realm; only this test's
        # events are listed.
        listed = self.get(f"/admin/realms/master/admin-events?direction=asc&authClient={self.admin_client}&dateFrom={started}&resourceTypes=REALM&resourcePath={created}")
        self.realm_ids["master"] = self.master_id
        observed = []
        for event in listed:
            summary = self.summary(event, "master")
            if summary["representation"] is not None:
                summary["representation"] = "kept"
            observed.append(summary)
        self.assertEqual(observed, [comparable(event) for event in REFERENCE["master/create-delete"]])


if __name__ == "__main__":
    unittest.main()
