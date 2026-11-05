#!/usr/bin/env python3
"""Capture pinned Keycloak user updates through the admin API."""
import json
import pathlib
import secrets

import oauth
from admin_realms import send_raw
from admin_users import user_summary
from tokens import login


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    callback = base + '/callback'
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [{'clientId': 'user-app', 'publicClient': True, 'redirectUris': [callback]}]}, admin, expected=201)
    observations = {}
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm

    def call(label, method, path, payload=None, raw=None):
        data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        response = send_raw(admin_base + path, method, data, auth)
        observation = user_summary(response, base, realm)
        parsed = json.loads(response[2]) if response[2] and response[1].get_content_type() == 'application/json' else None
        if isinstance(parsed, dict) and 'requiredActions' in parsed:
            observation['required_actions'] = sorted(parsed['requiredActions'])
        observations[label] = observation
        return response

    try:
        user = send_raw(admin_base + '/users', 'POST', json.dumps({'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}).encode(), auth)[1]['Location'].rsplit('/', 1)[1]
        send_raw(admin_base + '/users', 'POST', json.dumps({'username': 'other-user', 'enabled': True, 'email': 'other@example.invalid'}).encode(), auth)
        path = '/users/' + user
        call('update/first-name', 'PUT', path, {'firstName': 'Changed'})
        call('get/after-first-name', 'GET', path)
        call('update/email', 'PUT', path, {'email': 'New@Example.invalid'})
        call('get/after-email', 'GET', path)
        call('update/email-verified', 'PUT', path, {'emailVerified': True})
        call('get/after-email-verified', 'GET', path)
        call('update/duplicate-email', 'PUT', path, {'email': 'other@example.invalid'})
        call('update/username', 'PUT', path, {'username': 'renamed-user'})
        call('get/after-username', 'GET', path)
        call('update/same-username', 'PUT', path, {'username': 'reference-user', 'lastName': 'Same'})
        call('get/after-same-username', 'GET', path)
        call('update/clear-first-name', 'PUT', path, {'firstName': ''})
        call('get/after-clear', 'GET', path)
        call('update/required-actions', 'PUT', path, {'requiredActions': ['UPDATE_PASSWORD']})
        call('get/after-required-actions', 'GET', path)
        call('update/clear-required-actions', 'PUT', path, {'requiredActions': []})
        call('update/disable', 'PUT', path, {'enabled': False})
        call('get/after-disable', 'GET', path)
        try:
            login(base + '/realms/' + realm, 'user-app', None, password)
            observations['login/disabled'] = {'completed': True}
        except AssertionError:
            observations['login/disabled'] = {'completed': False}
        # The default profile requires a first name, which an earlier case cleared.
        call('update/enable', 'PUT', path, {'enabled': True, 'firstName': 'Restored'})
        tokens, _ = login(base + '/realms/' + realm, 'user-app', None, password)
        observations['login/enabled'] = {'completed': bool(tokens.get('access_token'))}
        call('update/other-id-in-body', 'PUT', path, {'id': '00000000-0000-0000-0000-000000000000', 'lastName': 'Body'})
        call('get/after-other-id', 'GET', path)
        call('update/unknown', 'PUT', '/users/00000000-0000-0000-0000-000000000000', {'firstName': 'x'})
        call('update/malformed', 'PUT', path, raw=b'{')
        call('update/invalid-email', 'PUT', path, {'email': 'not-an-email'})
        baseline = pathlib.Path(__file__).with_name('admin-user-update-observations.json')
        assert record or baseline.exists(), 'reference user update baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference user update case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference user update case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Partial user updates of names, email and its verification, username, required actions and enabled state, with errors and the effect of disabling on browser login; selected fields only.', 'normalization': 'The random realm name and base URL are replaced with placeholders.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference user update check failed: {detail}') from None
