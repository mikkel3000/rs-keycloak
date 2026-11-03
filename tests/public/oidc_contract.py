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
import urllib.parse


class LoginForm(html.parser.HTMLParser):
    action = None

    def handle_starttag(self, tag, attrs):
        if tag == "form":
            self.action = dict(attrs).get("action")


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
        for mode, replay_kind in (
            ("public", "code"), ("public", "refresh"), ("public", "refresh_race"),
            ("basic", "refresh"), ("post", "refresh"),
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
            query = urllib.parse.urlencode({
                "client_id": client, "redirect_uri": redirect, "response_type": "code",
                "scope": "openid", "code_challenge_method": "S256", "code_challenge": challenge,
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
            status, headers, _ = request("POST", form.action, {"username": username, "password": password}, cookie.split(";", 1)[0])
            assert status in (302, 303), "Password login failed"
            location = urllib.parse.urlsplit(headers["location"])
            params = urllib.parse.parse_qs(location.query)
            assert location.scheme + "://" + location.netloc + location.path == redirect
            assert params["state"] == [state]
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
            claims = verify_jwt(tokens["id_token"], keys)
            access = verify_jwt(tokens["access_token"], keys)
            assert access["sub"] == claims["sub"] and access["iss"] == issuer
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
            if replay_kind == "code":
                status, _, body = token_request(token_form)
                assert status == 400 and json.loads(body)["error"] == "invalid_grant", "Code replay accepted"
            else:
                refresh = {"grant_type": "refresh_token", "client_id": client, "refresh_token": tokens["refresh_token"]}
                # An unrelated client and scope expansion must not consume the token.
                status, _, _ = token_request(dict(refresh, client_id=client + "-other"))
                assert status in (400, 401)
                status, _, body = token_request(dict(refresh, scope="openid admin"))
                assert status == 400 and json.loads(body)["error"] == "invalid_scope"
                if replay_kind == "refresh_race":
                    with ThreadPoolExecutor(max_workers=2) as executor:
                        replies = list(executor.map(lambda _: token_request(refresh), range(2)))
                    assert sorted(reply[0] for reply in replies) == [200, 400], "Concurrent refresh had multiple winners"
                    rotated = json.loads(next(reply[2] for reply in replies if reply[0] == 200))
                else:
                    status, _, body = token_request(refresh)
                    assert status == 200, "Refresh rotation failed"
                    rotated = json.loads(body)
                    assert rotated["refresh_token"] != tokens["refresh_token"]
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
        print("Public OAuth login, PKCE, refresh rotation and replay race checks passed")
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
