#!/usr/bin/env python3
"""Capture pinned Keycloak offline_access: offline refresh tokens and their lifecycle."""
import base64
import hashlib
import http.cookiejar
import json
import pathlib
import secrets
import urllib.parse
import urllib.request

import oauth
from admin_realms import send_raw
from logout import get_without_redirects
from tokens import send


def claims(token):
    return json.loads(oauth.unbase64(token.split('.')[1]))


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    callback = base + '/callback'
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none'}, admin, expected=201)
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm
    issuer = base + '/realms/' + realm
    endpoint = issuer + '/protocol/openid-connect'
    send_raw(admin_base + '/clients', 'POST', json.dumps({'clientId': 'user-app', 'publicClient': True, 'redirectUris': [callback]}).encode(), auth)
    user_id = send_raw(admin_base + '/users', 'POST', json.dumps({'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True}).encode(), auth)[1]['Location'].rsplit('/', 1)[1]
    send_raw(admin_base + f'/users/{user_id}/reset-password', 'PUT', json.dumps({'type': 'password', 'value': password, 'temporary': False}).encode(), auth)
    client_id = json.loads(send_raw(admin_base + '/clients?clientId=user-app', 'GET', None, auth)[2])[0]['id']
    observations = {}

    def login(scope):
        policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https', 'wss'))
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), oauth.Redirects())
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        query = urllib.parse.urlencode({'client_id': 'user-app', 'redirect_uri': callback, 'response_type': 'code', 'scope': scope, 'state': 'state', 'code_challenge': challenge, 'code_challenge_method': 'S256'})
        _, _, body = send(endpoint + '/auth?' + query, opener=browser)
        form = oauth.Form()
        form.feed(body.decode())
        _, headers, _ = send(form.action, list((form.fields | {'username': 'reference-user', 'password': password, 'credentialId': ''}).items()), opener=browser)
        code = urllib.parse.parse_qs(urllib.parse.urlparse(headers['Location']).query)['code'][0]
        _, _, body = send(endpoint + '/token', [('grant_type', 'authorization_code'), ('client_id', 'user-app'), ('redirect_uri', callback), ('code', code), ('code_verifier', verifier)])
        return json.loads(body)

    def refresh(label, token):
        status, _, body = send(endpoint + '/token', [('grant_type', 'refresh_token'), ('client_id', 'user-app'), ('refresh_token', token)])
        parsed = json.loads(body)
        observation = {'status': status, 'error': parsed.get('error'), 'error_description': parsed.get('error_description')}
        if status == 200:
            observation |= {'refresh_typ': claims(parsed['refresh_token'])['typ'], 'refresh_expires_in': parsed['refresh_expires_in'], 'scope': sorted(parsed['scope'].split())}
        observations[label] = observation
        return parsed

    try:
        tokens = login('openid offline_access')
        refresh_claims = claims(tokens['refresh_token'])
        observations['login'] = {'scope': sorted(tokens['scope'].split()), 'refresh_typ': refresh_claims['typ'], 'refresh_has_exp': 'exp' in refresh_claims, 'refresh_expires_in': tokens['refresh_expires_in'], 'access_scope': sorted(claims(tokens['access_token'])['scope'].split()), 'realm_roles': sorted(role.replace(realm, '{realm}') for role in claims(tokens['access_token']).get('realm_access', {}).get('roles', []))}
        rotated = refresh('refresh/first', tokens['refresh_token'])
        status, _, body = send_raw(admin_base + f'/users/{user_id}/offline-sessions/{client_id}', 'GET', None, auth)
        listed = json.loads(body)
        observations['admin/offline-sessions'] = {'status': status, 'count': len(listed), 'fields': sorted({field for item in listed for field in item})}
        status, _, body = send_raw(admin_base + f'/clients/{client_id}/offline-session-count', 'GET', None, auth)
        observations['admin/offline-count'] = {'status': status, 'body': json.loads(body)}
        status, _, body = send_raw(admin_base + f'/users/{user_id}/sessions', 'GET', None, auth)
        observations['admin/online-sessions'] = {'status': status, 'count': len(json.loads(body))}
        logout = get_without_redirects(endpoint + '/logout?' + urllib.parse.urlencode({'id_token_hint': tokens['id_token'], 'post_logout_redirect_uri': callback}))
        observations['logout/browser'] = {'status': logout[0]}
        refresh('refresh/after-browser-logout', rotated['refresh_token'])
        status, _, body = send_raw(admin_base + f'/users/{user_id}/logout', 'POST', None, auth)
        observations['admin/user-logout'] = {'status': status}
        refresh('refresh/after-user-logout', rotated['refresh_token'])
        second = login('openid offline_access')
        status, _, _ = send(endpoint + '/revoke', [('token', second['refresh_token']), ('client_id', 'user-app')])
        observations['revoke/offline'] = {'status': status}
        refresh('refresh/after-revoke', second['refresh_token'])
        third = login('openid offline_access')
        status, _, body = send_raw(admin_base + f'/users/{user_id}/consents/user-app', 'DELETE', None, auth)
        observations['admin/revoke-consent'] = {'status': status}
        refresh('refresh/after-consent-revoke', third['refresh_token'])
        online = login('openid')
        observations['login/online'] = {'refresh_typ': claims(online['refresh_token'])['typ'], 'scope': sorted(online['scope'].split())}
        baseline = pathlib.Path(__file__).with_name('offline-access-observations.json')
        assert record or baseline.exists(), 'reference offline access baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference offline access case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference offline access case changed: {label}: {observations[label]}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'offline_access logins: offline refresh token shape, refresh, admin offline session listing and count, and the effect of browser logout, admin user logout, revocation and consent revocation; selected fields only.', 'normalization': 'No identifiers or token values are kept.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)
