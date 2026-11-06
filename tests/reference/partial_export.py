#!/usr/bin/env python3
"""Capture pinned Keycloak realm partial export through the admin API."""
import json
import pathlib
import secrets

import oauth
from admin_realms import send_raw


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True}, admin, expected=201)
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm
    observations = {}
    secret = secrets.token_urlsafe(40)

    def setup(method, path, payload=None):
        status, headers, body = send_raw(admin_base + path, method, json.dumps(payload).encode() if payload is not None else None, auth)
        assert status < 300, f'setup {method} {path}: {status}'
        return headers, body

    def export(label, query):
        status, headers, body = send_raw(admin_base + '/partial-export' + query, 'POST', None, auth)
        parsed = json.loads(body) if body else None
        observation = {'status': status, 'content_type': headers.get('Content-Type')}
        if isinstance(parsed, dict) and 'realm' in parsed:
            clients = {item['clientId']: item for item in parsed.get('clients', [])}
            app = clients.get('export-app', {})
            observation |= {
                'fields_count': len(parsed),
                'has': sorted(key for key in ('clients', 'roles', 'groups', 'users', 'clientScopes', 'defaultRole', 'requiredActions', 'components') if key in parsed),
                'client_ids': sorted(clients),
                'secret': app.get('secret'),
                'realm_roles': sorted(role['name'].replace(realm, '{realm}') for role in parsed.get('roles', {}).get('realm', [])),
                'client_roles': sorted(parsed.get('roles', {}).get('client', {}).get('export-app', []) and [role['name'] for role in parsed['roles']['client']['export-app']]),
                'groups': sorted(group['path'] for group in parsed.get('groups', [])),
                'group_roles': next((group.get('realmRoles') for group in parsed.get('groups', []) if group['name'] == 'export-group'), None),
            }
        elif isinstance(parsed, dict):
            observation['body'] = parsed
        observations[label] = observation

    try:
        setup('POST', '/roles', {'name': 'export-role'})
        app = setup('POST', '/clients', {'clientId': 'export-app', 'secret': secret, 'serviceAccountsEnabled': True})[0]['Location'].rsplit('/', 1)[1]
        setup('POST', f'/clients/{app}/roles', {'name': 'app-role'})
        group = setup('POST', '/groups', {'name': 'export-group'})[0]['Location'].rsplit('/', 1)[1]
        role = json.loads(setup('GET', '/roles/export-role')[1])
        setup('POST', f'/groups/{group}/role-mappings/realm', [{'id': role['id'], 'name': 'export-role'}])
        setup('POST', '/users', {'username': 'export-user', 'enabled': True})
        export('export/default', '')
        export('export/groups-roles', '?exportGroupsAndRoles=true')
        export('export/clients', '?exportClients=true')
        export('export/everything', '?exportGroupsAndRoles=true&exportClients=true')
        status, _, body = send_raw(base + '/admin/realms/missing-realm/partial-export', 'POST', None, auth)
        observations['export/unknown-realm'] = {'status': status, 'body': json.loads(body) if body else None}
        baseline = pathlib.Path(__file__).with_name('partial-export-observations.json')
        assert record or baseline.exists(), 'reference partial export baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference partial export case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference partial export case changed: {label}: {observations[label]}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Realm partial export with and without groups, roles and clients: which sections appear, client secrets masked, roles and groups listed, users left out; names and selected values only.', 'normalization': 'The random realm name is replaced with a placeholder; secrets are kept only as the reference masks them.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)
