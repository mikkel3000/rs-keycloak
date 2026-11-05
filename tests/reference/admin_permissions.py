#!/usr/bin/env python3
"""Capture pinned Keycloak admin access granted by realm-management roles."""
import json
import pathlib
import secrets

import oauth
from admin_realms import send_raw

ROLES = ['none', 'query-users', 'view-users', 'manage-users', 'query-clients', 'view-clients', 'manage-clients', 'view-realm', 'manage-realm', 'query-groups', 'create-client', 'realm-admin']


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, other = 'reference-' + secrets.token_hex(6), 'reference-' + secrets.token_hex(6)
    for name in (realm, other):
        oauth.request(base + '/admin/realms', {'realm': name, 'enabled': True, 'sslRequired': 'none'}, admin, expected=201)
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm
    observations = {}

    def admin_call(method, path, payload=None, prefix=admin_base):
        status, headers, body = send_raw(prefix + path, method, json.dumps(payload).encode() if payload is not None else None, auth)
        assert status < 300, f'setup {method} {path}: {status}'
        return headers, body

    try:
        clients = json.loads(admin_call('GET', '/clients?clientId=realm-management')[1])
        management = clients[0]['id']
        tokens = {}
        for role in ROLES:
            secret = secrets.token_urlsafe(40)
            headers, _ = admin_call('POST', '/clients', {'clientId': 'sa-' + role, 'secret': secret, 'serviceAccountsEnabled': True, 'standardFlowEnabled': False})
            client = headers['Location'].rsplit('/', 1)[1]
            user = json.loads(admin_call('GET', f'/clients/{client}/service-account-user')[1])['id']
            if role != 'none':
                described = json.loads(admin_call('GET', f'/clients/{management}/roles/{role}')[1])
                admin_call('POST', f'/users/{user}/role-mappings/clients/{management}', [{'id': described['id'], 'name': role}])
            _, body = oauth.request(base + f'/realms/{realm}/protocol/openid-connect/token', [('grant_type', 'client_credentials'), ('client_id', 'sa-' + role), ('client_secret', secret)])
            tokens[role] = json.loads(body)['access_token']
        target_user = admin_call('POST', '/users', {'username': 'target-user', 'enabled': True})[0]['Location'].rsplit('/', 1)[1]
        target_client = admin_call('POST', '/clients', {'clientId': 'target-client', 'publicClient': True})[0]['Location'].rsplit('/', 1)[1]
        admin_call('POST', '/groups', {'name': 'target-group'})
        operations = [
            ('realm/get', 'GET', '', None),
            ('realm/update', 'PUT', '', {'displayName': 'Changed'}),
            ('users/list', 'GET', '/users', None),
            ('users/count', 'GET', '/users/count', None),
            ('users/get', 'GET', f'/users/{target_user}', None),
            ('users/create', 'POST', '/users', {'username': 'new-{role}', 'enabled': True}),
            ('users/role-mappings', 'GET', f'/users/{target_user}/role-mappings/realm', None),
            ('clients/list', 'GET', '/clients', None),
            ('clients/get', 'GET', f'/clients/{target_client}', None),
            ('clients/create', 'POST', '/clients', {'clientId': 'new-{role}', 'publicClient': True}),
            ('clients/update', 'PUT', f'/clients/{target_client}', {'enabled': True}),
            ('roles/list', 'GET', '/roles', None),
            ('roles/create', 'POST', '/roles', {'name': 'new-{role}'}),
            ('groups/list', 'GET', '/groups', None),
            ('groups/create', 'POST', '/groups', {'name': 'new-{role}'}),
        ]
        for role, token in tokens.items():
            headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
            for label, method, path, payload in operations:
                data = json.dumps(payload).replace('{role}', role).encode() if payload is not None else None
                status, response_headers, body = send_raw(admin_base + path, method, data, headers)
                parsed = json.loads(body) if body and response_headers.get_content_type() == 'application/json' else None
                observations[f'{role}/{label}'] = {'status': status, 'error': parsed.get('error') if isinstance(parsed, dict) else None}
                if label == 'realm/get' and status == 200:
                    observations[f'{role}/{label}']['fields'] = sorted(parsed)
            for label, method, path in [('other-realm/get', 'GET', f'/admin/realms/{other}'), ('other-realm/users', 'GET', f'/admin/realms/{other}/users'), ('realms/list', 'GET', '/admin/realms'), ('realms/create', 'POST', '/admin/realms')]:
                data = json.dumps({'realm': f'created-{secrets.token_hex(4)}'}).encode() if method == 'POST' else None
                status, response_headers, body = send_raw(base + path, method, data, headers)
                parsed = json.loads(body) if body and response_headers.get_content_type() == 'application/json' else None
                observation = {'status': status, 'error': parsed.get('error') if isinstance(parsed, dict) else None}
                if isinstance(parsed, list):
                    observation['realms'] = sorted(item['realm'].replace(realm, '{realm}') for item in parsed)
                    observation['fields'] = sorted({field for item in parsed for field in item})
                observations[f'{role}/{label}'] = observation
        baseline = pathlib.Path(__file__).with_name('admin-permission-observations.json')
        assert record or baseline.exists(), 'reference admin permission baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference admin permission case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference admin permission case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Admin API access for service-account tokens of a realm holding one realm-management role each, across realm, user, client, role and group operations, another realm, and realm listing and creation; status and error only.', 'normalization': 'The managed realm name is replaced with a placeholder.', 'observations': observations}
    finally:
        for name in (realm, other):
            oauth.request(base + '/admin/realms/' + name, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference admin permission check failed: {detail}') from None
