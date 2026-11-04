#!/usr/bin/env python3
"""Capture pinned Keycloak user administration behavior via public HTTP only."""
import json
import pathlib
import secrets

import oauth
from admin_realms import send_raw
from tokens import login


def user_summary(response, base, realm):
    status, headers, body = response
    parsed = json.loads(body) if body and headers.get_content_type() == 'application/json' else None
    location = headers.get('Location')
    result = {
        'status': status,
        'content_type': headers.get('Content-Type'),
        'location_pattern': location.replace(base, '{base}').replace(realm, '{realm}').rsplit('/', 1)[0] + '/{id}' if location else None,
        'empty_body': not body,
    }
    if isinstance(parsed, dict):
        result['body_fields'] = sorted(parsed)
        result['body'] = {key: parsed[key] for key in ['error', 'error_description', 'errorMessage', 'field', 'username', 'enabled', 'email', 'emailVerified', 'firstName', 'lastName'] if key in parsed}
    elif isinstance(parsed, list):
        result['list_length'] = len(parsed)
        result['item_fields'] = sorted(parsed[0]) if parsed else []
        result['usernames'] = sorted(item.get('username') for item in parsed)
        result['enabled_by_username'] = {item.get('username'): item.get('enabled') for item in parsed}
    elif isinstance(parsed, int):
        result['value'] = parsed
    return result


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    password = secrets.token_urlsafe(40)
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [{'clientId': 'login-app', 'publicClient': True, 'standardFlowEnabled': True, 'redirectUris': [base + '/callback'], 'attributes': {'pkce.code.challenge.method': 'S256'}}]}, admin, expected=201)
    observations = {}
    users = '/admin/realms/' + realm + '/users'

    def call(label, method, path, token=admin, payload=None, raw=None):
        data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        headers = {'Authorization': 'Bearer ' + token} if token else {}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        response = send_raw(base + path, method, data, headers)
        observations[label] = user_summary(response, base, realm)
        return response

    try:
        created = call('create/success', 'POST', users, payload={'username': 'Reference-User', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'Reference@Example.invalid', 'emailVerified': True})
        user_id = created[1]['Location'].rsplit('/', 1)[1]
        call('create/duplicate-case', 'POST', users, payload={'username': 'reference-user', 'enabled': True})
        call('create/missing-username', 'POST', users, payload={'enabled': True})
        call('create/disabled', 'POST', users, payload={'username': 'disabled-user', 'enabled': False})
        call('create/default-enabled', 'POST', users, payload={'username': 'default-user'})
        call('create/duplicate-email', 'POST', users, payload={'username': 'other-user', 'email': 'reference@example.invalid'})
        call('create/no-token', 'POST', users, token=None, payload={'username': 'nobody'})
        call('create/unknown-realm', 'POST', '/admin/realms/unknown-' + secrets.token_hex(4) + '/users', payload={'username': 'nobody'})
        call('create/malformed-json', 'POST', users, raw=b'{')
        call('get/success', 'GET', users + '/' + user_id)
        call('get/unknown', 'GET', users + '/00000000-0000-0000-0000-000000000000')
        call('search/exact', 'GET', users + '?username=reference-user&exact=true')
        call('search/prefix', 'GET', users + '?username=reference')
        call('search/all', 'GET', users)
        call('count', 'GET', users + '/count')
        call('password/success', 'PUT', users + '/' + user_id + '/reset-password', payload={'type': 'password', 'value': password, 'temporary': False})
        call('password/empty', 'PUT', users + '/' + user_id + '/reset-password', payload={'type': 'password', 'value': '', 'temporary': False})
        call('password/unknown-user', 'PUT', users + '/00000000-0000-0000-0000-000000000000/reset-password', payload={'type': 'password', 'value': password, 'temporary': False})
        issuer = base + '/realms/' + realm
        # tokens.login signs in as reference-user and asserts a 200 code exchange.
        tokens, _ = login(issuer, 'login-app', None, password)
        observations['login/after-reset'] = {'status': 200, 'preferred_username': json.loads(oauth.unbase64(tokens['access_token'].split('.')[1])).get('preferred_username')}
        call('delete/success', 'DELETE', users + '/' + user_id)
        call('delete/repeat', 'DELETE', users + '/' + user_id)
        for observation in observations.values():
            for key, value in observation.get('body', {}).items():
                if isinstance(value, str):
                    observation['body'][key] = value.replace(realm, '{realm}')
        baseline = pathlib.Path(__file__).with_name('admin-user-observations.json')
        assert record or baseline.exists(), 'reference admin user baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference admin user case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference admin user case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'User create, read, search, count, password reset and delete through the admin API; field names and selected fixed values only.', 'normalization': 'The random realm name and base URL are replaced with {realm} and {base}; created user IDs are replaced with {id}.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference admin user check failed: {detail}') from None
