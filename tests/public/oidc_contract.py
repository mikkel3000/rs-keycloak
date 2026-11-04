"""Public OAuth flow over the local transport behind the configured HTTPS issuer."""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import html.parser
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import tempfile
import urllib.request

import cors_contract
import urllib.parse


class LoginForm(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
        self.method = None
        self.fields = {}
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.action = attrs.get("action")
            self.method = attrs.get("method")
        if tag == "input" and attrs.get("type") == "hidden":
            self.fields[attrs["name"]] = attrs.get("value", "")
        if tag == "script":
            self.scripts.append(attrs.get("nonce"))


def verify_jwt(token, keys):
    header, payload, signature = token.split(".")
    decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    metadata = json.loads(decode(header))
    assert metadata["alg"] == "RS256"
    key = next(key for key in keys if key["kid"] == metadata["kid"])
    modulus = int.from_bytes(decode(key["n"]), "big")
    exponent = int.from_bytes(decode(key["e"]), "big")
    width = (modulus.bit_length() + 7) // 8
    raw_signature = decode(signature)
    assert len(raw_signature) == width
    signature_number = int.from_bytes(raw_signature, "big")
    assert signature_number < modulus
    encoded = pow(signature_number, exponent, modulus).to_bytes(width, "big")
    # RFC 8017 EMSA-PKCS1-v1_5, SHA-256 DigestInfo; independent of Rust signer.
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
    digest_info += hashlib.sha256((header + "." + payload).encode()).digest()
    expected = b"\x00\x01" + b"\xff" * (width - len(digest_info) - 3) + b"\x00" + digest_info
    assert encoded == expected, "JWT signature did not match published JWKS"
    return json.loads(decode(payload))


def adapter_source():
    source = Path(tempfile.gettempdir()) / "rs-keycloak-js-26.2.2.mjs"
    expected = "af74b351e2aca48ab26c0e681e3ee5e056aef7faee1dc6f383f2d9611ac6870f"
    if not source.exists():
        url = "https://raw.githubusercontent.com/keycloak/keycloak-js/26.2.2/lib/keycloak.js"
        with urllib.request.urlopen(url, timeout=20) as response:
            data = response.read(512 * 1024)
        assert hashlib.sha256(data).hexdigest() == expected, "Adapter source digest differs"
        source.write_bytes(data)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == expected, "Cached adapter digest differs"
    return source


def run(binary, username, password, prefix=""):
    binary = str(Path(binary).resolve())
    client = "oauth-" + secrets.token_hex(8)
    redirect = "https://client.example.test/callback"
    setup = subprocess.run(
        [binary, "client", "add-public", "master", client, redirect],
        capture_output=True, timeout=10, check=False,
    )
    assert setup.returncode == 0, "OAuth client setup failed"
    public_client = client
    cors_contract.register(binary, public_client)
    confidential_client = client + "-confidential"
    client_secret = secrets.token_urlsafe(40) + ":+%/"
    for _ in range(2):
        setup = subprocess.run(
            [binary, "client", "add-confidential", "master", confidential_client, redirect],
            input=client_secret.encode(), capture_output=True, timeout=10, check=False,
        )
        assert setup.returncode == 0, "Confidential client setup was not idempotent"
        assert client_secret.encode() not in setup.stdout + setup.stderr
    pem = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        capture_output=True, timeout=15, check=True,
    ).stdout
    der = subprocess.run(
        ["openssl", "pkcs8", "-topk8", "-nocrypt", "-outform", "DER"],
        input=pem, capture_output=True, timeout=5, check=True,
    ).stdout
    with socket.socket() as port_socket, socket.socket() as management_socket:
        port_socket.bind(("127.0.0.1", 0))
        management_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]
        management = management_socket.getsockname()[1]
    environment = os.environ.copy()
    environment.update({
        "RS_KEYCLOAK_HTTP_LISTEN": f"127.0.0.1:{port}",
        "RS_KEYCLOAK_MANAGEMENT_LISTEN": f"127.0.0.1:{management}",
        "RS_KEYCLOAK_ISSUER": "https://login.example.test" + prefix,
        "RS_KEYCLOAK_SIGNING_KEY_PKCS8": base64.b64encode(der).decode(),
    })
    process = subprocess.Popen(
        [binary, "serve"], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

    def request(method, path, data=None, cookie=None, bearer=None, authorization=None):
        headers = {}
        if data is not None:
            data = urllib.parse.urlencode(data)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie:
            headers["Cookie"] = cookie
        if authorization:
            headers["Authorization"] = authorization
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request(method, prefix + path if not path.startswith(prefix + "/realms/") else path, data, headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    try:
        discovery = "/realms/master/.well-known/openid-configuration"
        deadline = time.monotonic() + 15
        while True:
            assert process.poll() is None, "OAuth server exited at startup"
            try:
                status, _, body = request("GET", discovery)
                if status == 200:
                    break
            except OSError:
                pass
            assert time.monotonic() < deadline, "OAuth server did not start"
            time.sleep(0.05)
        issuer = "https://login.example.test" + prefix + "/realms/master"
        assert json.loads(body)["issuer"] == issuer
        token_path = "/realms/master/protocol/openid-connect/token"
        for malformed, error in (
            ({}, "invalid_request"),
            ({"grant_type": "unknown_grant"}, "unsupported_grant_type"),
            ({"grant_type": "authorization_code"}, "invalid_request"),
            ([("grant_type", "refresh_token"), ("client_id", client), ("client_id", client), ("refresh_token", "x" * 64)], "invalid_request"),
        ):
            status, headers, body = request("POST", token_path, malformed)
            assert status == 400, "Token input error used the wrong HTTP status"
            assert json.loads(body)["error"] == error
            assert headers.get("cache-control") == "no-store"
        callback = subprocess.run(
            ["node", str(Path(__file__).with_name("keycloak_adapter.mjs")), str(adapter_source())],
            input=json.dumps({"login": {"username": username, "password": password}, "client": public_client, "prefix": prefix, "transport": f"http://127.0.0.1:{port}"}).encode(),
            capture_output=True, timeout=15, check=False,
        )
        assert callback.returncode == 0, callback.stderr.decode()
        callback_tokens = json.loads(callback.stdout)
        status, _, body = request("GET", "/realms/master/protocol/openid-connect/userinfo", bearer=callback_tokens["access_token"])
        assert status == 200, "Adapter callback did not produce usable tokens"
        cors_contract.run(port, prefix, public_client, confidential_client, callback_tokens)
        for mode, replay_kind in (
            ("public", "code"), ("public", "fragment"), ("public", "form_post"), ("public", "refresh"), ("public", "refresh_race"), ("public", "adapter"),
            ("basic", "refresh"), ("post", "refresh"),
            ("public", "revoke_access"), ("public", "revoke_refresh"), ("public", "revoke_race"), ("basic", "revoke_refresh"),
        ):
            client = public_client if mode == "public" else confidential_client

            def token_request(data, path=token_path):
                data = dict(data)
                authorization = None
                if mode == "basic":
                    if data.get("client_id") == client:
                        del data["client_id"]
                    credentials = urllib.parse.quote_plus(client) + ":" + urllib.parse.quote_plus(client_secret)
                    authorization = "Basic " + base64.b64encode(credentials.encode()).decode()
                elif mode == "post":
                    data["client_secret"] = client_secret
                return request("POST", path, data, authorization=authorization)

            verifier = secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
            response_mode = replay_kind if replay_kind in ("fragment", "form_post") else "query"
            if response_mode == "form_post":
                state += "\"<>&'"
            query = urllib.parse.urlencode({
                "client_id": client, "redirect_uri": redirect, "response_type": "code",
                "scope": "openid", "response_mode": response_mode, "code_challenge_method": "S256", "code_challenge": challenge,
                "state": state, "nonce": nonce, "unrecognized_extension": "ignored",
            })
            status, headers, body = request("GET", "/realms/master/protocol/openid-connect/auth?" + query)
            assert status == 200, "Authorization request failed"
            cookie = headers["set-cookie"]
            assert all(flag in cookie for flag in ("Secure", "HttpOnly", "SameSite="))
            form = LoginForm()
            form.feed(body.decode())
            assert form.action and form.action.startswith(prefix + "/realms/"), "Login form has wrong context path"
            assert "Path=" + prefix + "/realms/master/login-actions/" in cookie
            # Explicit cookie transport models the HTTPS proxy without weakening
            # Secure-cookie policy or persisting the password in a browser profile.
            status, _, _ = request("POST", form.action, {"username": username, "password": password})
            assert status >= 400, "Login accepted without browser binding"
            status, headers, response_body = request("POST", form.action, {"username": username, "password": password}, cookie.split(";", 1)[0])
            if response_mode == "form_post":
                assert status == 200 and headers["content-type"].startswith("text/html")
                returned_form = LoginForm()
                returned_form.feed(response_body.decode())
                assert returned_form.action == redirect and returned_form.method == "post"
                assert len(returned_form.scripts) == 1 and returned_form.scripts[0]
                assert "'nonce-" + returned_form.scripts[0] + "'" in headers["content-security-policy"]
                assert state.encode() not in response_body, "State was not escaped in form HTML"
                assert headers["cache-control"] == "no-store"
                params = {key: [value] for key, value in returned_form.fields.items()}
            else:
                assert status in (302, 303), "Password login failed"
                location = urllib.parse.urlsplit(headers["location"])
                assert location.scheme + "://" + location.netloc + location.path == redirect
                params = urllib.parse.parse_qs(location.fragment if response_mode == "fragment" else location.query)
                assert not (location.query if response_mode == "fragment" else location.fragment)
            assert params["state"] == [state] and params["iss"] == [issuer]
            token_form = {
                "grant_type": "authorization_code", "code": params["code"][0],
                "client_id": client, "redirect_uri": redirect, "code_verifier": verifier,
                "unrecognized_extension": "ignored",
            }
            token_path = "/realms/master/protocol/openid-connect/token"
            if mode != "public":
                for rejected in (token_form, dict(token_form, client_secret="incorrect")):
                    status, _, body = request("POST", token_path, rejected)
                    assert status == 401 and json.loads(body)["error"] == "unauthorized_client", "Client authentication error differs from Keycloak"
                wrong_basic = base64.b64encode((urllib.parse.quote_plus(client) + ":incorrect").encode()).decode()
                status, headers, body = request("POST", token_path, token_form, authorization="Basic " + wrong_basic)
                assert status == 401 and json.loads(body)["error"] == "unauthorized_client"
                # Pinned Keycloak omits the challenge even for Basic failures.
                assert "www-authenticate" not in headers, "Basic failure differs from pinned Keycloak"
            status, headers, body = token_request(token_form)
            assert status == 200, "Code exchange failed"
            assert headers.get("cache-control") == "no-store"
            tokens = json.loads(body)
            status, _, body = request("GET", "/realms/master/protocol/openid-connect/certs")
            assert status == 200
            keys = json.loads(body)["keys"]
            refresh_claims = verify_jwt(tokens["refresh_token"], keys)
            assert refresh_claims["typ"] == "Refresh" and refresh_claims["aud"] == issuer
            assert refresh_claims["azp"] == client and refresh_claims["exp"] > refresh_claims["iat"]
            assert 0 < tokens["refresh_expires_in"] <= 1800
            claims = verify_jwt(tokens["id_token"], keys)
            access = verify_jwt(tokens["access_token"], keys)
            assert access["sub"] == claims["sub"] and access["iss"] == issuer
            assert access["typ"] == "Bearer" and refresh_claims["sub"] == claims["sub"]
            status, _, _ = token_request({"grant_type": "refresh_token", "client_id": client, "refresh_token": tokens["access_token"]})
            assert status == 400, "Access token accepted as refresh token"
            tampered = tokens["refresh_token"].split(".")
            tampered[2] = ("A" if tampered[2][0] != "A" else "B") + tampered[2][1:]
            status, _, _ = token_request({"grant_type": "refresh_token", "client_id": client, "refresh_token": ".".join(tampered)})
            assert status == 400, "Tampered refresh signature accepted"


            assert claims["iss"] == issuer and claims["aud"] == client
            assert claims["nonce"] == nonce and claims["exp"] > claims["iat"]
            introspection = token_path + "/introspect"
            for inspected in (tokens["access_token"], tokens["refresh_token"]):
                status, inspection_headers, body = token_request({"token": inspected, "client_id": client}, path=introspection)
                if mode == "public":
                    assert status == 403 and json.loads(body)["error"] == "invalid_request", "Public client introspection allowed"
                else:
                    metadata = json.loads(body)
                    assert status == 200 and metadata["active"] is True
                    assert metadata["sub"] == claims["sub"] and metadata["client_id"] == client
                    assert inspection_headers.get("cache-control") == "no-store"
            if mode != "public":
                status, _, body = token_request({"token": "unknown", "client_id": client}, path=introspection)
                assert status == 200 and json.loads(body) == {"active": False}
                status, _, body = token_request({"client_id": client}, path=introspection)
                assert status == 400 and json.loads(body)["error_description"] == "Token not provided."
                status, _, body = token_request({"client_id": client, "token": tokens["access_token"], "token_type_hint": "unknown"}, path=introspection)
                assert status == 400 and json.loads(body)["error_description"] == "Unsupported token type."
                status, _, body = request("POST", introspection, {"client_id": client, "client_secret": "wrong", "token": tokens["access_token"]})
                assert status == 401 and json.loads(body)["error"] == "invalid_client"
            else:
                status, _, body = request("POST", introspection, {"client_id": confidential_client, "client_secret": client_secret, "token": tokens["access_token"]})
                assert status == 200 and json.loads(body) == {"active": False}, "Wrong audience introspected token"
            userinfo = "/realms/master/protocol/openid-connect/userinfo"
            status, _, _ = request("GET", userinfo, bearer=tokens["refresh_token"])
            assert status == 401, "Refresh token accepted as access token"
            status, _, body = request("GET", userinfo, bearer=tokens["access_token"])
            assert status == 200 and json.loads(body)["sub"] == claims["sub"]
            if mode != "public":
                previous_secret = client_secret
                client_secret = secrets.token_urlsafe(40) + ":+%/"
                rotated_secret = subprocess.run(
                    [binary, "client", "rotate-secret", "master", client],
                    input=(previous_secret + "\n" + client_secret + "\n").encode(),
                    capture_output=True, timeout=10, check=False,
                )
                assert rotated_secret.returncode == 0, "Client secret rotation failed"
                for secret in (previous_secret, client_secret):
                    assert secret.encode() not in rotated_secret.stdout + rotated_secret.stderr
                status, _, body = request("POST", token_path, {
                    "grant_type": "refresh_token", "client_id": client,
                    "client_secret": previous_secret, "refresh_token": tokens["refresh_token"],
                })
                assert status == 401 and json.loads(body)["error"] == "unauthorized_client", "Old secret survived rotation"
            if replay_kind.startswith("revoke_"):
                revoke = token_path.removesuffix("/token") + "/revoke"
                status, _, body = token_request({"client_id": client}, path=revoke)
                assert status == 400 and json.loads(body)["error_description"] == "Token not provided"
                status, _, body = token_request({"client_id": client, "token": "unknown"}, path=revoke)
                assert status == 200 and json.loads(body)["error"] == "invalid_token"
                status, _, body = token_request({"client_id": client, "token": tokens["id_token"]}, path=revoke)
                assert status == 400 and json.loads(body)["error"] == "unsupported_token_type"
                outsider = {"client_id": confidential_client, "client_secret": client_secret} if mode == "public" else {"client_id": public_client}
                status, _, body = request("POST", revoke, dict(outsider, token=tokens["refresh_token"]))
                assert status == 400 and json.loads(body)["error_description"] == "Unmatching clients"
                status, _, _ = request("GET", userinfo, bearer=tokens["access_token"])
                assert status == 200, "Other client revoked the session"
                refresh = {"grant_type": "refresh_token", "client_id": client, "refresh_token": tokens["refresh_token"]}
                if replay_kind == "revoke_access":
                    status, _, body = token_request({"client_id": client, "token": tokens["access_token"]}, path=revoke)
                    assert status == 200 and not body
                    status, _, _ = request("GET", userinfo, bearer=tokens["access_token"])
                    assert status == 401
                    status, _, body = token_request(refresh)
                    assert status == 200, "Access revocation unexpectedly revoked refresh"
                    replacement = json.loads(body)
                    status, _, _ = request("GET", userinfo, bearer=replacement["access_token"])
                    assert status == 200
                    status, _, body = token_request({"client_id": client, "token": replacement["refresh_token"]}, path=revoke)
                    assert status == 200 and not body
                    status, _, _ = request("GET", userinfo, bearer=replacement["access_token"])
                    assert status == 401, "Refresh revocation left replacement access usable"
                elif replay_kind == "revoke_race":
                    with ThreadPoolExecutor(max_workers=2) as executor:
                        revoking = executor.submit(token_request, {"client_id": client, "token": tokens["refresh_token"]}, path=revoke)
                        refreshing = executor.submit(token_request, refresh)
                        revoked_reply, refresh_reply = revoking.result(), refreshing.result()
                    assert revoked_reply[0] == 200
                    assert refresh_reply[0] in (200, 400), "Revocation race failed transactionally"
                    if refresh_reply[0] == 200:
                        replacement = json.loads(refresh_reply[2])
                        status, _, _ = request("GET", userinfo, bearer=replacement["access_token"])
                        assert status == 401, "Concurrent refresh escaped revocation"
                        status, _, _ = token_request(dict(refresh, refresh_token=replacement["refresh_token"]))
                        assert status == 400
                else:
                    status, _, body = token_request({"client_id": client, "token": tokens["refresh_token"]}, path=revoke)
                    assert status == 200 and not body
                status, _, body = token_request(refresh)
                assert status == 400 and json.loads(body)["error"] == "invalid_grant"
                status, _, _ = token_request({"client_id": client, "token": tokens["refresh_token"]}, path=revoke)
                assert status == 200, "Repeat revocation was not idempotent"
            elif replay_kind == "code":
                status, _, body = token_request(token_form)
                assert status == 400 and json.loads(body)["error"] == "invalid_grant", "Code replay accepted"
            else:
                refresh = {"grant_type": "refresh_token", "client_id": client, "refresh_token": tokens["refresh_token"]}
                # An unrelated client and scope expansion must not consume the token.
                status, _, _ = token_request(dict(refresh, client_id=client + "-other"))
                assert status in (400, 401)
                status, _, body = token_request(dict(refresh, scope="openid admin"))
                assert status == 400 and json.loads(body)["error"] == "invalid_scope"
                if replay_kind == "adapter":
                    adapter = subprocess.run(
                        ["node", str(Path(__file__).with_name("keycloak_adapter.mjs")), str(adapter_source())],
                        input=json.dumps({"tokens": tokens, "client": client, "prefix": prefix, "transport": f"http://127.0.0.1:{port}"}).encode(),
                        capture_output=True, timeout=15, check=False,
                    )
                    assert adapter.returncode == 0, "Pinned Keycloak JS init/refresh failed"
                    rotated = json.loads(adapter.stdout)
                    verify_jwt(rotated["refresh_token"], keys)
                    status, _, body = token_request(refresh)
                    assert status == 400 and json.loads(body)["error"] == "invalid_grant"
                elif replay_kind == "refresh_race":
                    with ThreadPoolExecutor(max_workers=2) as executor:
                        replies = list(executor.map(lambda _: token_request(refresh), range(2)))
                    assert sorted(reply[0] for reply in replies) == [200, 400], "Concurrent refresh had multiple winners"
                    rotated = json.loads(next(reply[2] for reply in replies if reply[0] == 200))
                else:
                    status, _, body = token_request(refresh)
                    assert status == 200, "Refresh rotation failed"
                    rotated = json.loads(body)
                    assert rotated["refresh_token"] != tokens["refresh_token"]
                    next_refresh = verify_jwt(rotated["refresh_token"], keys)
                    assert next_refresh["jti"] != refresh_claims["jti"]
                    assert next_refresh["exp"] == refresh_claims["exp"], "Rotation extended the fixed family lifetime"

                    refreshed_id = verify_jwt(rotated["id_token"], keys)
                    assert refreshed_id["sub"] == claims["sub"] and refreshed_id["auth_time"] == claims["auth_time"]
                    status, _, _ = request("GET", userinfo, bearer=rotated["access_token"])
                    assert status == 200
                    status, _, body = token_request(refresh)
                    assert status == 400 and json.loads(body)["error"] == "invalid_grant", "Refresh replay accepted"
                status, _, _ = token_request(dict(refresh, refresh_token=rotated["refresh_token"]))
                assert status == 400, "Refresh replay left its successor usable"
                status, _, _ = request("GET", userinfo, bearer=rotated["access_token"])
                assert status == 401, "Refresh replay left new access token active"
            status, _, _ = request("GET", userinfo, bearer=tokens["access_token"])
            assert status == 401, "Replay did not revoke userinfo access"
            if mode != "public":
                for inspected in (tokens["access_token"], tokens["refresh_token"]):
                    status, _, body = token_request({"token": inspected, "client_id": client}, path=introspection)
                    assert status == 200 and json.loads(body) == {"active": False}, "Revoked session still introspects active"

        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, "OAuth shutdown failed"
        assert password.encode() not in stdout + stderr, "Password appeared in server output"
        assert client_secret.encode() not in stdout + stderr, "Client secret appeared in server output"
        print("Public OAuth, introspection, refresh replay and pinned adapter checks passed")
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
