"""Client protocol mappers compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/protocol-mapper-observations.json:
mappers in client creation and update, as the upstream test framework's
OAuth client carries an audience mapper, the protocol-mappers resources,
and the audience mapper in tokens.

Known difference, listed in IMPLEMENTATION.md: the reference's default
role mappings add the `account` audience, and this server names the
token's own client as its first audience, so token audiences are compared
without `account` and, in the code flow, without the token's own client.
"""

import json
import secrets
import unittest

from fixture import ENDPOINT, ISSUER_BASE
from login_case import CALLBACK, LoginCase, reference

REFERENCE = reference("protocol-mapper-observations.json")
AUDIENCE = {
    "name": "audience-test-app",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-audience-mapper",
    "config": {"included.custom.audience": "test-app", "access.token.claim": "true"},
}


def mapper_summary(mapper):
    return {"fields": sorted(mapper), "name": mapper.get("name"), "protocol": mapper.get("protocol"), "protocolMapper": mapper.get("protocolMapper"), "consentRequired": mapper.get("consentRequired"), "config": mapper.get("config")}


def without(audience, *names):
    names = set(names) | {"account"}
    audience = audience if isinstance(audience, list) else [audience]
    return sorted(name for name in audience if name not in names)


def claims(token):
    import base64
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


class ProtocolMappersContract(LoginCase):
    REALMS = {"mappers": {}}
    secret = secrets.token_urlsafe(40)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.ids = {}
        cls.created = {}
        cases = {
            "test-app": {"clientId": "test-app", "secret": cls.secret, "serviceAccountsEnabled": True, "redirectUris": [CALLBACK], "protocolMappers": [AUDIENCE]},
            "no-mappers": {"clientId": "plain-app"},
            "duplicate-names": {"clientId": "twice-app", "protocolMappers": [AUDIENCE, AUDIENCE]},
            "unnamed": {"clientId": "unnamed-app", "protocolMappers": [{key: value for key, value in AUDIENCE.items() if key != "name"}]},
            "public": {"clientId": "id-app", "publicClient": True, "redirectUris": [CALLBACK], "protocolMappers": [{
                "name": "audience-in-id-token", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                "config": {"included.client.audience": "test-app", "id.token.claim": "true", "access.token.claim": "true"},
            }]},
        }
        name = cls.names["mappers"]
        for label, payload in cases.items():
            status, headers, body = cls.request("POST", f"/admin/realms/{name}/clients", {"Authorization": "Bearer " + cls.token, "Content-Type": "application/json"}, body=json.dumps(payload))
            cls.created[label] = {"status": status, "body": json.loads(body) if body else None}
            if headers.get("location"):
                cls.ids[label] = headers["location"].rsplit("/", 1)[1]
        cls.user = cls.new_user("mappers", "alice")

    def mappers(self, label, path="/protocol-mappers/models", method="GET", payload=None):
        return self.realm_admin("mappers", f"/clients/{self.ids[label]}{path}", method, payload)

    def post(self, label, payload):
        name = self.names["mappers"]
        status, headers, body = self.request("POST", f"/admin/realms/{name}/clients/{self.ids['test-app']}/protocol-mappers/models", {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}, body=json.dumps(payload))
        location = headers.get("location")
        observed = {"status": status, "body": json.loads(body) if body else None, "location": location.replace(ISSUER_BASE, "{base}").replace(self.ids["test-app"], "{client}").rsplit("/", 1)[0] if location else None}
        self.assertEqual(self.normalized(observed), REFERENCE[f"post/{label}"], label)
        return location.rsplit("/", 1)[1] if location else None

    def test_client_creation(self):
        for label, observed in self.created.items():
            self.assertEqual(observed, REFERENCE[f"create-client/{label}"], label)
        _, client = self.realm_admin("mappers", f"/clients/{self.ids['test-app']}")
        self.assertEqual([mapper_summary(mapper) for mapper in client["protocolMappers"]], REFERENCE["client/test-app"])
        _, client = self.realm_admin("mappers", f"/clients/{self.ids['no-mappers']}")
        self.assertEqual({"has_field": "protocolMappers" in client}, REFERENCE["client/no-mappers"])

    def test_models_resources(self):
        status, listed = self.mappers("test-app")
        self.assertEqual({"status": status, "mappers": [mapper_summary(mapper) for mapper in listed]}, REFERENCE["models/list"])
        audience_id = listed[0]["id"]
        status, one = self.mappers("test-app", f"/protocol-mappers/models/{audience_id}")
        self.assertEqual({"status": status, "mapper": mapper_summary(one), "id_matches": one["id"] == audience_id}, REFERENCE["models/one"])
        for protocol in ("openid-connect", "saml"):
            status, listed = self.mappers("test-app", f"/protocol-mappers/protocol/{protocol}")
            self.assertEqual({"status": status, "names": [mapper["name"] for mapper in listed]}, REFERENCE[f"models/protocol-{protocol}"], protocol)

    def test_create_update_delete(self):
        second = self.post("client-audience", {"name": "client-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": {"included.client.audience": "plain-app"}})
        self.post("duplicate-name", dict(AUDIENCE))
        self.post("unknown-type", {"name": "unknown", "protocol": "openid-connect", "protocolMapper": "no-such-mapper", "config": {}})
        self.post("missing-name", {"protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": {}})
        self.post("missing-protocol", {"name": "no-protocol", "protocolMapper": "oidc-audience-mapper", "config": {}})
        models = "/protocol-mappers/models/"
        self.assertEqual(mapper_summary(self.mappers("test-app", models + second)[1]), REFERENCE["models/created"])
        cases = [
            ("rename-and-config", second, {"id": second, "name": "renamed", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": {"included.custom.audience": "other-audience", "introspection.token.claim": "false"}}),
            ("id-mismatch", second, {"id": "other-id", "name": "renamed", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": {}}),
            ("unknown", "no-such-mapper-id", {"name": "x", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": {}}),
        ]
        for label, mapper_id, payload in cases:
            status, body = self.mappers("test-app", models + mapper_id, "PUT", payload)
            self.assertEqual({"status": status, "body": body}, REFERENCE[f"put/{label}"], label)
            if label == "rename-and-config":
                self.assertEqual(mapper_summary(self.mappers("test-app", models + second)[1]), REFERENCE["models/updated"])
        status, body = self.mappers("test-app", models + second, "DELETE")
        self.assertEqual({"status": status, "body": body}, REFERENCE["delete"])
        self.assertEqual(dict(zip(("status", "body"), self.mappers("test-app", models + second))), REFERENCE["delete/after"])
        self.assertEqual(dict(zip(("status", "body"), self.mappers("test-app", models + second, "DELETE"))), REFERENCE["delete/again"])

    def test_client_updates(self):
        status, body = self.mappers("no-mappers", "/protocol-mappers/add-models", "POST", [
            {"name": "first", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": {"included.custom.audience": "one"}},
            {"name": "second", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": {"included.custom.audience": "two"}},
        ])
        names = lambda: sorted(mapper["name"] for mapper in self.mappers("no-mappers")[1])  # noqa: E731
        self.assertEqual({"status": status, "body": body, "names": names()}, REFERENCE["add-models"])
        _, client = self.realm_admin("mappers", f"/clients/{self.ids['no-mappers']}")
        status, _ = self.realm_admin("mappers", f"/clients/{self.ids['no-mappers']}", "PUT", {key: value for key, value in client.items() if key != "protocolMappers"})
        self.assertEqual({"status": status, "names": names()}, REFERENCE["client-put/without-field"])
        status, _ = self.realm_admin("mappers", f"/clients/{self.ids['no-mappers']}", "PUT", {"clientId": "plain-app", "protocolMappers": [
            {"name": "second", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": {"included.custom.audience": "changed"}},
            {"name": "third", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": {}},
        ]})
        listed = self.mappers("no-mappers")[1]
        self.assertEqual({"status": status, "mappers": sorted([mapper["name"], mapper["config"]] for mapper in listed)}, REFERENCE["client-put/replace"])
        status, _ = self.realm_admin("mappers", f"/clients/{self.ids['no-mappers']}", "PUT", {"clientId": "plain-app", "protocolMappers": []})
        self.assertEqual({"status": status, "names": [mapper["name"] for mapper in self.mappers("no-mappers")[1]]}, REFERENCE["client-put/empty"])

    def test_tokens(self):
        realm = self.names["mappers"]
        token_path = f"/realms/{realm}/protocol/openid-connect/token"
        status, _, body = self.request("POST", token_path, form={"grant_type": "client_credentials", "client_id": "test-app", "client_secret": self.secret})
        self.assertEqual(status, 200)
        token = json.loads(body)["access_token"]
        access = claims(token)
        expected = REFERENCE["token/client-credentials"]
        self.assertEqual({"aud": without(access["aud"]), "azp": access["azp"]}, {"aud": without(expected["aud"]), "azp": expected["azp"]})
        status, _, body = self.request("POST", token_path + "/introspect", form={"token": token, "client_id": "test-app", "client_secret": self.secret})
        introspected = json.loads(body)
        expected = REFERENCE["token/introspection"]
        self.assertEqual({"active": introspected["active"], "aud": without(introspected["aud"])}, {"active": expected["active"], "aud": without(expected["aud"])})
        browser = self.browser("mappers")
        browser.client = "id-app"
        tokens = browser.exchange(browser.sign_in("alice", self.password))
        expected = REFERENCE["token/code-flow"]
        observed = {"access_aud": without(claims(tokens["access_token"])["aud"], "id-app"), "id_aud": without(claims(tokens["id_token"])["aud"], "id-app")}
        self.assertEqual(observed, {"access_aud": without(expected["access_aud"], "id-app"), "id_aud": without(expected["id_aud"], "id-app")})


class ProtocolMappersDisabledAudienceContract(LoginCase):
    """A named client audience is left out while that client is disabled."""

    REALMS = {"mappers": {}}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        name = cls.names["mappers"]
        assert cls.admin("POST", f"/admin/realms/{name}/clients", {"clientId": "test-app", "enabled": False})[0] == 201
        assert cls.admin("POST", f"/admin/realms/{name}/clients", {"clientId": "id-app", "publicClient": True, "redirectUris": [CALLBACK], "protocolMappers": [{
            "name": "audience-in-id-token", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": "test-app", "id.token.claim": "true", "access.token.claim": "true"},
        }]})[0] == 201
        cls.new_user("mappers", "alice")

    def test_disabled_audience_client(self):
        browser = self.browser("mappers")
        browser.client = "id-app"
        tokens = browser.exchange(browser.sign_in("alice", self.password))
        expected = REFERENCE["token/disabled-audience-client"]
        self.assertEqual({"access_aud": without(claims(tokens["access_token"])["aud"], "id-app")}, {"access_aud": without(expected["access_aud"], "id-app")})


del ENDPOINT

if __name__ == "__main__":
    unittest.main()
