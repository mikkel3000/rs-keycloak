#!/usr/bin/env python3
"""Capture pinned Keycloak partial import of groups, client roles and mappings."""
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
    payload = {
        'ifResourceExists': 'FAIL',
        'roles': {'realm': [{'name': 'imported-role'}], 'client': {'imported-app': [{'name': 'imported-app-role'}]}},
        'clients': [{'clientId': 'imported-app', 'publicClient': True}],
        'groups': [{'name': 'imported-group', 'path': '/imported-group', 'realmRoles': ['imported-role'], 'clientRoles': {'imported-app': ['imported-app-role']}, 'subGroups': [{'name': 'imported-child', 'path': '/imported-group/imported-child'}]}],
        'users': [{'username': 'imported-user', 'enabled': True, 'realmRoles': ['imported-role'], 'clientRoles': {'imported-app': ['imported-app-role']}, 'groups': ['/imported-group/imported-child']}],
    }

    def get(path):
        return json.loads(send_raw(admin_base + path, 'GET', None, auth)[2])

    try:
        status, _, body = send_raw(admin_base + '/partialImport', 'POST', json.dumps(payload).encode(), auth)
        parsed = json.loads(body)
        observations['import'] = {'status': status, 'added': parsed.get('added'), 'results': sorted([item['action'], item['resourceType'], item['resourceName']] for item in parsed.get('results', [])), 'error': parsed.get('error') or parsed.get('errorMessage')}
        if status == 200:
            group = next(item for item in get('/groups') if item['name'] == 'imported-group')
            full = get(f"/groups/{group['id']}")
            observations['group'] = {'realm_roles': full.get('realmRoles'), 'client_roles': full.get('clientRoles'), 'children': sorted(item['name'] for item in get(f"/groups/{group['id']}/children"))}
            client = get('/clients?clientId=imported-app')[0]
            observations['client-roles'] = sorted(role['name'] for role in get(f"/clients/{client['id']}/roles"))
            user = get('/users?username=imported-user&exact=true')[0]
            observations['user'] = {
                'realm_roles': sorted(role['name'].replace(realm, '{realm}') for role in get(f"/users/{user['id']}/role-mappings/realm")),
                'client_roles': sorted(role['name'] for role in get(f"/users/{user['id']}/role-mappings/clients/{client['id']}")),
                'groups': sorted(item['path'] for item in get(f"/users/{user['id']}/groups")),
            }
            status, _, body = send_raw(admin_base + '/partialImport', 'POST', json.dumps(payload | {'ifResourceExists': 'SKIP'}).encode(), auth)
            parsed = json.loads(body)
            observations['import/skip'] = {'status': status, 'skipped': parsed.get('skipped'), 'results': sorted([item['action'], item['resourceType'], item['resourceName']] for item in parsed.get('results', []))}
        baseline = pathlib.Path(__file__).with_name('partial-import-group-observations.json')
        assert record or baseline.exists(), 'reference partial import group baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference partial import group case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference partial import group case changed: {label}: {observations[label]}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Partial import of client roles, a group tree with paths and role mappings, and a user with role mappings and group membership, then again with SKIP; names and counts only.', 'normalization': 'The random realm name is replaced with a placeholder.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)
