#!/usr/bin/env python3
"""Capture pinned Keycloak realm administration behavior via public HTTP only."""
import json
import pathlib
import secrets
import urllib.error
import urllib.request

import oauth
from tokens import send


def admin_summary(response, base):
    status, headers, body = response
    parsed = json.loads(body) if body and headers.get_content_type() == 'application/json' else None
    location = headers.get('Location')
    result = {
        'status': status,
        'content_type': headers.get('Content-Type'),
        'location': location.replace(base, '{base}') if location else None,
        'www_authenticate': headers.get('WWW-Authenticate'),
        'empty_body': not body,
    }
    if isinstance(parsed, dict):
        result['body_fields'] = sorted(parsed)
        result['body'] = {key: parsed[key] for key in ['error', 'error_description', 'errorMessage', 'enabled', 'realm', 'id'] if key in parsed and key != 'id'}
        result['has_id'] = 'id' in parsed
    elif isinstance(parsed, list):
        result['list_length'] = len(parsed)
    return result


def send_raw(url, method, data, headers):
    try:
        response = urllib.request.build_opener().open(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read(2 * 1024 * 1024)


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    plain, plain_secret = 'plain-' + secrets.token_hex(4), secrets.token_urlsafe(40)
    oauth.request(base + '/admin/realms/master/clients', {'clientId': plain, 'publicClient': False, 'secret': plain_secret, 'serviceAccountsEnabled': True, 'standardFlowEnabled': False}, admin, expected=201)
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', plain), ('client_secret', plain_secret)])
    unprivileged = json.loads(body)['access_token']
    observations = {}
    admin_headers = lambda token: {'Authorization': 'Bearer ' + token}

    def call(label, method, path, token=None, payload=None, raw=None):
        data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        headers = admin_headers(token) if token else {}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        response = send_raw(base + path, method, data, headers)
        observations[label] = admin_summary(response, base)
        return response

    try:
        call('create/no-token', 'POST', '/admin/realms', payload={'realm': realm, 'enabled': True})
        call('create/invalid-token', 'POST', '/admin/realms', 'not-a-token', {'realm': realm, 'enabled': True})
        call('create/unprivileged', 'POST', '/admin/realms', unprivileged, {'realm': realm, 'enabled': True})
        call('create/success', 'POST', '/admin/realms', admin, {'realm': realm, 'enabled': True})
        call('create/duplicate', 'POST', '/admin/realms', admin, {'realm': realm, 'enabled': True})
        call('create/missing-name', 'POST', '/admin/realms', admin, {'enabled': True})
        call('create/malformed-json', 'POST', '/admin/realms', admin, raw=b'{')
        call('get/success', 'GET', '/admin/realms/' + realm, admin)
        call('get/unknown', 'GET', '/admin/realms/unknown-' + secrets.token_hex(4), admin)
        call('get/unprivileged', 'GET', '/admin/realms/' + realm, unprivileged)
        call('get/no-token', 'GET', '/admin/realms/' + realm)
        call('discovery/new-realm', 'GET', '/realms/' + realm + '/.well-known/openid-configuration')
        call('delete/success', 'DELETE', '/admin/realms/' + realm, admin)
        call('delete/repeat', 'DELETE', '/admin/realms/' + realm, admin)
        call('discovery/deleted-realm', 'GET', '/realms/' + realm + '/.well-known/openid-configuration')
        call('create/disabled', 'POST', '/admin/realms', admin, {'realm': realm, 'enabled': False})
        call('discovery/disabled-realm', 'GET', '/realms/' + realm + '/.well-known/openid-configuration')
        call('get/disabled', 'GET', '/admin/realms/' + realm, admin)
        call('delete/disabled', 'DELETE', '/admin/realms/' + realm, admin)
        for observation in observations.values():
            if observation.get('location'):
                observation['location'] = observation['location'].replace(realm, '{realm}')
            if observation['www_authenticate']:
                observation['www_authenticate'] = observation['www_authenticate'].replace(realm, '{realm}')
            for key, value in observation.get('body', {}).items():
                if isinstance(value, str):
                    observation['body'][key] = value.replace(realm, '{realm}')
        baseline = pathlib.Path(__file__).with_name('admin-realm-observations.json')
        assert record or baseline.exists(), 'reference admin realm baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference admin realm case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference admin realm case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Realm create, read and delete through the admin API with bootstrap service-account, unprivileged and missing tokens; field names and selected fixed values only.', 'normalization': 'The random realm name in headers and body strings and the server base URL are replaced with {realm} and {base}.', 'observations': observations}
    finally:
        realm_exists = send(base + '/admin/realms/' + realm, extra_headers=admin_headers(admin))[0] == 200
        if realm_exists:
            oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)
        clients = json.loads(send(base + '/admin/realms/master/clients?clientId=' + plain, extra_headers=admin_headers(admin))[2])
        for client in clients:
            oauth.request(base + '/admin/realms/master/clients/' + client['id'], token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference admin realm check failed: {detail}') from None
