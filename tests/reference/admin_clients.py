#!/usr/bin/env python3
"""Capture pinned Keycloak client administration behavior via public HTTP only."""
import json
import pathlib
import re
import secrets

import oauth
from admin_realms import send_raw


SELECTED = ['clientId', 'enabled', 'publicClient', 'serviceAccountsEnabled', 'standardFlowEnabled', 'directAccessGrantsEnabled', 'implicitFlowEnabled', 'redirectUris', 'webOrigins', 'protocol', 'clientAuthenticatorType', 'bearerOnly', 'type', 'error', 'error_description', 'errorMessage']


def client_summary(response, base, realm):
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
        result['body'] = {key: parsed[key] for key in SELECTED if key in parsed}
        result['has_secret'] = bool(parsed.get('secret') or parsed.get('value'))
    elif isinstance(parsed, list):
        result['list_length'] = len(parsed)
        # A client created without clientId gets a random UUID as its clientId.
        result['client_ids'] = sorted(re.sub(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', '{generated}', item.get('clientId')) for item in parsed)
    return result


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True}, admin, expected=201)
    observations = {}
    clients = '/admin/realms/' + realm + '/clients'
    secret = secrets.token_urlsafe(40)

    def call(label, method, path, payload=None, raw=None, token=admin):
        data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        headers = {'Authorization': 'Bearer ' + token} if token else {}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        response = send_raw(base + path, method, data, headers)
        observations[label] = client_summary(response, base, realm)
        return response

    try:
        public = call('create/public', 'POST', clients, {'clientId': 'public-app', 'publicClient': True, 'redirectUris': ['https://app.example.invalid/callback'], 'webOrigins': ['https://app.example.invalid']})
        public_id = public[1]['Location'].rsplit('/', 1)[1]
        confidential = call('create/confidential', 'POST', clients, {'clientId': 'service-app', 'publicClient': False, 'secret': secret, 'serviceAccountsEnabled': True, 'standardFlowEnabled': False})
        confidential_id = confidential[1]['Location'].rsplit('/', 1)[1]
        defaults = call('create/defaults', 'POST', clients, {'clientId': 'default-app'})
        defaults_id = defaults[1]['Location'].rsplit('/', 1)[1]
        call('create/duplicate', 'POST', clients, {'clientId': 'public-app'})
        call('create/missing-client-id', 'POST', clients, {'publicClient': True})
        call('create/malformed-json', 'POST', clients, raw=b'{')
        call('create/unknown-realm', 'POST', '/admin/realms/unknown-' + secrets.token_hex(4) + '/clients', {'clientId': 'x'})
        call('create/no-token', 'POST', clients, {'clientId': 'x'}, token=None)
        call('get/public', 'GET', clients + '/' + public_id)
        call('get/confidential', 'GET', clients + '/' + confidential_id)
        call('get/defaults', 'GET', clients + '/' + defaults_id)
        call('get/unknown', 'GET', clients + '/00000000-0000-0000-0000-000000000000')
        call('search/client-id', 'GET', clients + '?clientId=public-app')
        call('search/client-id-unknown', 'GET', clients + '?clientId=missing-app')
        call('search/all-count', 'GET', clients)
        call('secret/get', 'GET', clients + '/' + confidential_id + '/client-secret')
        call('secret/get-public', 'GET', clients + '/' + public_id + '/client-secret')
        call('secret/regenerate', 'POST', clients + '/' + confidential_id + '/client-secret')
        call('service-account/user', 'GET', clients + '/' + confidential_id + '/service-account-user')
        call('service-account/public', 'GET', clients + '/' + public_id + '/service-account-user')
        call('delete/success', 'DELETE', clients + '/' + public_id)
        call('delete/repeat', 'DELETE', clients + '/' + public_id)
        for observation in observations.values():
            for key, value in observation.get('body', {}).items():
                if isinstance(value, str):
                    observation['body'][key] = value.replace(realm, '{realm}')
        baseline = pathlib.Path(__file__).with_name('admin-client-observations.json')
        assert record or baseline.exists(), 'reference admin client baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference admin client case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference admin client case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Client create, read, search, secret, service-account user and delete through the admin API; selected fields and fixed values only, secrets reduced to presence.', 'normalization': 'The random realm name and base URL are replaced with {realm} and {base}; created client IDs are replaced with {id}.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference admin client check failed: {detail}') from None
