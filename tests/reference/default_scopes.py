#!/usr/bin/env python3
"""Capture pinned Keycloak token claims for the default client scopes."""
import base64
import hashlib
import http.cookiejar
import json
import pathlib
import secrets
import urllib.parse
import urllib.request

import oauth
from tokens import send


def claims(token):
    return json.loads(oauth.unbase64(token.split('.')[1]))


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    callback = base + '/callback'
    user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [{'clientId': 'user-app', 'publicClient': True, 'redirectUris': [callback]}], 'users': [user]}, admin, expected=201)
    issuer = base + '/realms/' + realm
    observations = {}

    def login(label, scope):
        policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https', 'wss'))
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), oauth.Redirects())
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        query = urllib.parse.urlencode({'client_id': 'user-app', 'redirect_uri': callback, 'response_type': 'code', 'scope': scope, 'state': 'state', 'code_challenge': challenge, 'code_challenge_method': 'S256'})
        status, headers, body = send(issuer + '/protocol/openid-connect/auth?' + query, opener=browser)
        if status != 200:
            location = headers.get('Location') or ''
            observations[label] = {'authorize_status': status, 'error': urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get('error')}
            return
        form = oauth.Form()
        form.feed(body.decode())
        status, headers, _ = send(form.action, list((form.fields | {'username': 'reference-user', 'password': password, 'credentialId': ''}).items()), opener=browser)
        if 'Location' not in headers:
            observations[label] = {'login_status': status}
            return
        result = urllib.parse.parse_qs(urllib.parse.urlparse(headers['Location']).query)
        if 'code' not in result:
            observations[label] = {'callback_error': result.get('error')}
            return
        _, _, body = send(issuer + '/protocol/openid-connect/token', [('grant_type', 'authorization_code'), ('client_id', 'user-app'), ('redirect_uri', callback), ('code', result['code'][0]), ('code_verifier', verifier)])
        tokens = json.loads(body)
        access = claims(tokens['access_token'])
        identity = claims(tokens['id_token']) if 'id_token' in tokens else {}
        status, _, body = send(issuer + '/protocol/openid-connect/userinfo', bearer=tokens['access_token'])
        userinfo = json.loads(body) if body and status == 200 else {}
        observations[label] = {
            'has_id_token': 'id_token' in tokens,
            'userinfo_status': status,
            'response_scope': sorted(tokens['scope'].split()),
            'access_scope': sorted(access['scope'].split()),
            'access_claims': sorted(access),
            'id_claims': sorted(identity),
            'userinfo_claims': sorted(userinfo),
            'values': {key: (identity or userinfo).get(key) for key in ('preferred_username', 'email', 'email_verified', 'name', 'given_name', 'family_name')},
            'access_typ': access.get('typ'),
            'id_typ': identity.get('typ'),
        }

    try:
        login('scope/openid', 'openid')
        login('scope/openid-profile-email', 'openid profile email')
        login('scope/openid-email', 'openid email')
        login('scope/unknown', 'openid unknown-scope')
        login('scope/without-openid', 'profile')
        baseline = pathlib.Path(__file__).with_name('default-scope-observations.json')
        assert record or baseline.exists(), 'reference default scope baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference default scope case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference default scope case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Code-flow logins with openid, profile and email scope combinations, an unknown scope and no openid: granted scopes, access, ID token and userinfo claim names, and profile claim values.', 'normalization': 'None needed: only claim names, scopes and fixture profile values are kept.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference default scope check failed: {detail}') from None
