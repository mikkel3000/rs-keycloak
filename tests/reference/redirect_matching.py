#!/usr/bin/env python3
"""Capture pinned Keycloak redirect URI matching: wildcards and relative URIs."""
import base64
import hashlib
import json
import pathlib
import secrets
import urllib.parse
import urllib.request

import oauth
from tokens import send


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none'}, admin, expected=201)
    oauth.request(base + f'/admin/realms/{realm}/clients', {'clientId': 'rooted-app', 'publicClient': True, 'rootUrl': 'https://app.example.invalid', 'redirectUris': ['/cb', 'https://exact.example.invalid/*', 'https://query.example.invalid/cb?x=1']}, admin, expected=201)
    issuer = base + '/realms/' + realm
    observations = {}
    opener = urllib.request.build_opener(oauth.Redirects())

    def authorize(label, client, redirect):
        challenge = base64.urlsafe_b64encode(hashlib.sha256(secrets.token_bytes(32)).digest()).rstrip(b'=').decode()
        query = urllib.parse.urlencode({'client_id': client, 'redirect_uri': redirect, 'response_type': 'code', 'scope': 'openid', 'state': 'state', 'code_challenge': challenge, 'code_challenge_method': 'S256'})
        status, headers, body = send(issuer + '/protocol/openid-connect/auth?' + query, opener=opener)
        observations[label] = {'status': status, 'login_form': b'kc-form-login' in body or b'name="username"' in body, 'invalid_redirect': b'redirect_uri' in body and status == 400}

    try:
        account = base + f'/realms/{realm}/account'
        authorize('account-console/base', 'account-console', account + '/')
        authorize('account-console/deep', 'account-console', account + '/x/y?z=1')
        authorize('account-console/no-slash', 'account-console', account)
        authorize('account-console/other-path', 'account-console', base + f'/realms/{realm}/other')
        authorize('account-console/other-host', 'account-console', 'http://evil.example.invalid' + f'/realms/{realm}/account/')
        authorize('account-console/dot-segment', 'account-console', account + '/../other')
        authorize('rooted/relative', 'rooted-app', 'https://app.example.invalid/cb')
        authorize('rooted/relative-other-host', 'rooted-app', base + '/cb')
        authorize('rooted/wildcard', 'rooted-app', 'https://exact.example.invalid/any/path')
        authorize('rooted/wildcard-root', 'rooted-app', 'https://exact.example.invalid/')
        authorize('rooted/wildcard-bare', 'rooted-app', 'https://exact.example.invalid')
        authorize('rooted/wildcard-query', 'rooted-app', 'https://exact.example.invalid/p?q=1')
        authorize('rooted/wildcard-userinfo', 'rooted-app', 'https://user@exact.example.invalid/p')
        authorize('rooted/wildcard-other-port', 'rooted-app', 'https://exact.example.invalid:8443/p')
        authorize('rooted/exact-query', 'rooted-app', 'https://query.example.invalid/cb?x=1')
        authorize('rooted/exact-query-other', 'rooted-app', 'https://query.example.invalid/cb?x=2')
        authorize('rooted/exact-query-missing', 'rooted-app', 'https://query.example.invalid/cb')
        authorize('rooted/fragment', 'rooted-app', 'https://app.example.invalid/cb#f')
        authorize('rooted/case', 'rooted-app', 'https://APP.example.invalid/cb')
        baseline = pathlib.Path(__file__).with_name('redirect-matching-observations.json')
        assert record or baseline.exists(), 'reference redirect matching baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations == expected, 'reference redirect matching cases changed'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Authorization requests checking redirect URIs against the built-in account-console and a client with a root URL, relative, wildcard and query-bearing redirect URIs; status and page kind only.', 'normalization': 'None needed: no realm names or URLs are kept.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference redirect matching check failed: {detail}') from None
