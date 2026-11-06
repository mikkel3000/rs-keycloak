#!/usr/bin/env python3
"""Capture pinned Keycloak account API routes the account console uses."""
import base64
import hashlib
import http.cookiejar
import json
import pathlib
import secrets
import urllib.parse
import urllib.request

import oauth
from account_api import StopAt
from admin_realms import send_raw
from tokens import send


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    callback = base + '/callback'
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [{'clientId': 'plain-app', 'publicClient': True, 'redirectUris': [callback]}, {'clientId': 'unused-app', 'publicClient': True, 'redirectUris': [callback]}]}, admin, expected=201)
    oauth.request(base + '/admin/realms/' + realm + '/users', {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}, admin, expected=201)
    issuer = base + '/realms/' + realm
    observations = {}

    def user_tokens(client, redirect, scope='openid'):
        policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https', 'wss'))
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), StopAt(redirect))
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        query = urllib.parse.urlencode({'client_id': client, 'redirect_uri': redirect, 'response_type': 'code', 'scope': scope, 'state': 's', 'code_challenge': challenge, 'code_challenge_method': 'S256'})
        form = oauth.Form()
        form.feed(send(issuer + '/protocol/openid-connect/auth?' + query, opener=browser)[2].decode())
        _, headers, _ = send(form.action, list((form.fields | {'username': 'reference-user', 'password': password, 'credentialId': ''}).items()), opener=browser)
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(headers['Location']).query)['code'][0]
        _, _, body = send(issuer + '/protocol/openid-connect/token', [('grant_type', 'authorization_code'), ('client_id', client), ('redirect_uri', redirect), ('code', code), ('code_verifier', verifier)])
        return json.loads(body)

    def refresh(label, client, tokens):
        status, _, body = send(issuer + '/protocol/openid-connect/token', [('grant_type', 'refresh_token'), ('client_id', client), ('refresh_token', tokens['refresh_token'])])
        observations[label] = {'status': status, 'error': json.loads(body).get('error')}

    try:
        account = user_tokens('account-console', issuer + '/account/')
        plain = user_tokens('plain-app', callback, 'openid offline_access')
        api = issuer + '/account'
        headers = {'Authorization': 'Bearer ' + account['access_token'], 'Accept': 'application/json'}
        status, _, body = send_raw(api + '/applications', 'GET', None, headers)
        listed = json.loads(body)
        observations['applications'] = {
            'status': status,
            'fields': sorted({field for item in listed for field in item}),
            'apps': sorted([item['clientId'], item.get('inUse'), item.get('offlineAccess'), item.get('userConsentRequired'), 'effectiveUrl' in item] for item in listed),
        }
        status, _, body = send_raw(api + '/sessions/devices', 'GET', None, headers)
        devices = json.loads(body)
        observations['devices'] = {
            'status': status,
            'count': len(devices),
            'device_fields': sorted({field for item in devices for field in item}),
            'session_fields': sorted({field for item in devices for session in item.get('sessions', []) for field in session}),
            'sessions': sum(len(item.get('sessions', [])) for item in devices),
            'current': sorted(bool(session.get('current')) for item in devices for session in item.get('sessions', [])),
            'clients': sorted(sorted(client['clientId'] for client in session.get('clients', [])) for item in devices for session in item.get('sessions', [])),
        }
        status, _, body = send_raw(api + '/sessions', 'DELETE', None, headers)
        observations['sessions/delete-others'] = {'status': status, 'empty_body': not body}
        refresh('refresh/current-after-delete', 'account-console', account)
        refresh('refresh/other-online-after-delete', 'plain-app', plain)
        status, _, body = send_raw(api + '/applications/plain-app/consent', 'DELETE', None, headers)
        observations['applications/revoke-consent'] = {'status': status, 'empty_body': not body}
        status, _, body = send_raw(api + '/applications/missing-app/consent', 'DELETE', None, headers)
        observations['applications/revoke-unknown'] = {'status': status, 'body': json.loads(body) if body else None}
        status, _, body = send_raw(api + '/applications', 'GET', None, headers)
        observations['applications/after-revoke'] = {'apps': sorted([item['clientId'], item.get('inUse'), item.get('offlineAccess')] for item in json.loads(body))}
        baseline = pathlib.Path(__file__).with_name('account-console-api-observations.json')
        assert record or baseline.exists(), 'reference account console API baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference account console API case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference account console API case changed: {label}: {observations[label]}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Account API applications and device sessions, ending all other sessions, and removing an application grant; shapes and selected values only.', 'normalization': 'No identifiers are kept.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)
