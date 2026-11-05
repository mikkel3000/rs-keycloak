#!/usr/bin/env python3
"""Capture pinned Keycloak client updates through the admin API."""
import json
import pathlib
import secrets

import oauth
from admin_clients import client_summary
from admin_realms import send_raw
from tokens import send, summary


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none'}, admin, expected=201)
    observations = {}
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm
    token_endpoint = base + '/realms/' + realm + '/protocol/openid-connect/token'
    secret, other_secret = secrets.token_urlsafe(40), secrets.token_urlsafe(40)

    def clean(value):
        if isinstance(value, str):
            return value.replace(base, '{base}').replace(realm, '{realm}')
        if isinstance(value, list):
            return sorted(clean(item) for item in value)
        return value

    def call(label, method, path, payload=None, raw=None):
        data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        response = send_raw(admin_base + path, method, data, auth)
        observation = client_summary(response, base, realm)
        if 'body' in observation:
            observation['body'] = {key: clean(value) for key, value in observation['body'].items()}
        observations[label] = observation
        return response

    def grant(label, client_id, client_secret):
        observations[label] = summary(send(token_endpoint, [('grant_type', 'client_credentials'), ('client_id', client_id), ('client_secret', client_secret)]))

    try:
        created = send_raw(admin_base + '/clients', 'POST', json.dumps({'clientId': 'app', 'secret': secret, 'serviceAccountsEnabled': True, 'redirectUris': ['https://app.example.invalid/cb']}).encode(), auth)
        app = created[1]['Location'].rsplit('/', 1)[1]
        send_raw(admin_base + '/clients', 'POST', json.dumps({'clientId': 'taken', 'publicClient': True}).encode(), auth)
        grant('grant/before', 'app', secret)
        call('update/partial-disable', 'PUT', '/clients/' + app, {'enabled': False})
        call('get/after-disable', 'GET', '/clients/' + app)
        grant('grant/disabled', 'app', secret)
        call('update/enable', 'PUT', '/clients/' + app, {'enabled': True})
        call('update/redirects', 'PUT', '/clients/' + app, {'redirectUris': ['https://app.example.invalid/other'], 'webOrigins': ['https://app.example.invalid']})
        call('get/after-redirects', 'GET', '/clients/' + app)
        call('update/secret', 'PUT', '/clients/' + app, {'secret': other_secret})
        grant('grant/old-secret', 'app', secret)
        grant('grant/new-secret', 'app', other_secret)
        call('update/rename', 'PUT', '/clients/' + app, {'clientId': 'renamed'})
        call('get/after-rename', 'GET', '/clients/' + app)
        grant('grant/renamed', 'renamed', other_secret)
        call('update/duplicate-client-id', 'PUT', '/clients/' + app, {'clientId': 'taken'})
        call('update/other-id-in-body', 'PUT', '/clients/' + app, {'id': '00000000-0000-0000-0000-000000000000', 'description': 'x'})
        call('get/after-other-id', 'GET', '/clients/' + app)
        call('update/unknown', 'PUT', '/clients/00000000-0000-0000-0000-000000000000', {'enabled': True})
        call('update/malformed', 'PUT', '/clients/' + app, raw=b'{')
        call('update/flows', 'PUT', '/clients/' + app, {'standardFlowEnabled': False, 'serviceAccountsEnabled': False, 'consentRequired': True})
        call('get/after-flows', 'GET', '/clients/' + app)
        grant('grant/no-service-account', 'renamed', other_secret)
        call('update/to-public', 'PUT', '/clients/' + app, {'publicClient': True})
        call('get/after-public', 'GET', '/clients/' + app)
        call('secret/after-public', 'GET', f'/clients/{app}/client-secret')
        call('update/to-confidential', 'PUT', '/clients/' + app, {'publicClient': False})
        call('get/after-confidential', 'GET', '/clients/' + app)
        observations['update/no-token'] = client_summary(send_raw(admin_base + '/clients/' + app, 'PUT', b'{"enabled": false}', {'Content-Type': 'application/json'}), base, realm)
        baseline = pathlib.Path(__file__).with_name('admin-client-update-observations.json')
        assert record or baseline.exists(), 'reference client update baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference client update case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference client update case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Partial client updates of enabled state, URLs, secret, clientId, flows and client type, with their errors and effect on client-credentials grants; names and selected fields only.', 'normalization': 'The random realm name and base URL are replaced with placeholders; secrets are reduced to presence.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference client update check failed: {detail}') from None
