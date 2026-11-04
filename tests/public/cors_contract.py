"""Public browser-origin behavior and rejection before token mutations."""

import http.client
import json
import subprocess
import urllib.parse


def register(binary, client):
    origin = "https://app.example.test"
    for _ in range(2):
        result = subprocess.run([binary, "client", "add-web-origin", "master", client, origin], capture_output=True, timeout=10, check=False)
        assert result.returncode == 0, "Origin registration was not idempotent"
    for bad in ("*", "null", "https://app.example.test/path", "https://app.example.test/", "http://remote.example.test"):
        result = subprocess.run([binary, "client", "add-web-origin", "master", client, bad], capture_output=True, timeout=10, check=False)
        assert result.returncode != 0, "Unsafe or noncanonical origin was accepted"


def run(port, prefix, client, other_client, tokens):
    origin = "https://app.example.test"
    bad = "https://other.example.test"
    token = prefix + "/realms/master/protocol/openid-connect/token"
    userinfo = prefix + "/realms/master/protocol/openid-connect/userinfo"
    def request(method, path, headers=None, form=None):
        body = urllib.parse.urlencode(form) if form is not None else None
        headers = dict(headers or {})
        if form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request(method, path, body, headers)
            result = connection.getresponse()
            return result.status, dict(result.getheaders()), result.read()
        finally:
            connection.close()
    preflight = {"Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization, content-type"}
    for endpoint in (token, prefix + "/realms/master/protocol/openid-connect/token/introspect", prefix + "/realms/master/protocol/openid-connect/revoke"):
        status, headers, _ = request("OPTIONS", endpoint, preflight)
        assert status in (200, 204) and headers.get("access-control-allow-origin") == origin
        assert headers.get("access-control-allow-credentials") == "true"
        assert "Origin" in headers.get("vary", "")
    status, headers, _ = request("OPTIONS", token, dict(preflight, Origin=bad))
    assert status == 200 and headers.get("access-control-allow-origin") == bad
    status, headers, _ = request("OPTIONS", token, dict(preflight, **{"Access-Control-Request-Headers": "x-unapproved"}))
    assert status == 200 and "x-unapproved" not in headers.get("access-control-allow-headers", "").lower()
    for endpoint in (prefix + "/realms/master/.well-known/openid-configuration", prefix + "/realms/master/protocol/openid-connect/certs"):
        for method in ("GET", "OPTIONS"):
            status, headers, _ = request(method, endpoint, {"Origin": bad, "Access-Control-Request-Method": "GET"})
            assert status == 200 and headers.get("access-control-allow-origin") == bad
            assert headers.get("access-control-allow-credentials") == "true"
    refresh = {"grant_type": "refresh_token", "client_id": client, "refresh_token": tokens["refresh_token"]}
    revoke = prefix + "/realms/master/protocol/openid-connect/revoke"
    status, _, _ = request("POST", revoke, {"Origin": bad}, {"client_id": client, "token": tokens["refresh_token"]})
    assert status == 403, "Unregistered origin reached revocation endpoint"
    status, _, _ = request("POST", token, {"Origin": bad}, refresh)
    assert status == 403, "Unregistered origin reached token endpoint"
    status, _, _ = request("POST", token, {"Origin": origin}, dict(refresh, client_id=other_client))
    assert status == 403, "Origin registered to another client was accepted"
    status, headers, _ = request("GET", userinfo, {"Origin": origin, "Authorization": "Bearer " + tokens["access_token"]})
    assert status == 200 and headers.get("access-control-allow-origin") == origin
    status, _, _ = request("GET", userinfo, {"Origin": bad, "Authorization": "Bearer " + tokens["access_token"]})
    assert status == 403, "Unregistered origin reached userinfo"
    status, headers, body = request("POST", token, {"Origin": origin}, refresh)
    assert status == 200 and headers.get("access-control-allow-origin") == origin, "Rejected origin consumed the refresh token"
    assert json.loads(body).get("access_token")
