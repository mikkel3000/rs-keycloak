#!/usr/bin/env python3
"""Capture pinned Keycloak user creation with initial credentials."""
import http.cookiejar
import json
import pathlib
import secrets
import urllib.parse
import urllib.request

import oauth
from admin_realms import send_raw
from tokens import send


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    callback = base + '/callback'
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none'}, admin, expected=201)
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm
    issuer = base + '/realms/' + realm
    send_raw(admin_base + '/clients', 'POST', json.dumps({'clientId': 'user-app', 'publicClient': True, 'redirectUris': [callback]}).encode(), auth)
    observations = {}
    profile = {'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'emailVerified': True}

    def create(label, username, credentials):
        status, headers, body = send_raw(admin_base + '/users', 'POST', json.dumps(profile | {'username': username, 'email': f'{username}@example.invalid', 'credentials': credentials}).encode(), auth)
        observation = {'status': status, 'body': json.loads(body) if body else None}
        if status == 201:
            user = json.loads(send_raw(headers['Location'], 'GET', None, auth)[2])
            stored = json.loads(send_raw(headers['Location'] + '/credentials', 'GET', None, auth)[2])
            observation |= {'required_actions': sorted(user['requiredActions']), 'credential_types': sorted(item['type'] for item in stored), 'credential_fields': sorted({field for item in stored for field in item})}
        observations[label] = observation

    def login(label, username, password):
        query = urllib.parse.urlencode({'client_id': 'user-app', 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 's'})
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https')))), oauth.Redirects())
        form = oauth.Form()
        form.feed(send(issuer + '/protocol/openid-connect/auth?' + query, opener=browser)[2].decode())
        status, headers, body = send(form.action, list((form.fields | {'username': username, 'password': password, 'credentialId': ''}).items()), opener=browser)
        location = headers.get('Location') or ''
        observations[label] = {'status': status, 'code': 'code=' in location, 'update_password_page': b'password-new' in body}

    try:
        password = secrets.token_urlsafe(24)
        create('create/password', 'plain-user', [{'type': 'password', 'value': password, 'temporary': False}])
        login('login/password', 'plain-user', password)
        create('create/temporary', 'temp-user', [{'type': 'password', 'value': password, 'temporary': True}])
        login('login/temporary', 'temp-user', password)
        create('create/default-temporary', 'default-user', [{'type': 'password', 'value': password}])
        create('create/empty-value', 'empty-user', [{'type': 'password', 'value': '', 'temporary': False}])
        create('create/unknown-type', 'otp-user', [{'type': 'otp', 'value': '123456'}])
        create('create/two-passwords', 'two-user', [{'type': 'password', 'value': password, 'temporary': False}, {'type': 'password', 'value': password + 'x', 'temporary': False}])
        login('login/two-passwords-first', 'two-user', password)
        create('create/empty-list', 'none-user', [])
        baseline = pathlib.Path(__file__).with_name('user-credential-create-observations.json')
        assert record or baseline.exists(), 'reference user credential baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference user credential case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference user credential case changed: {label}: {observations[label]}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'User creation with password credentials, temporary and not, defaults, empty and unknown types and two passwords, with the stored credentials and the following login; selected values only.', 'normalization': 'No identifiers or secrets are kept.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)
