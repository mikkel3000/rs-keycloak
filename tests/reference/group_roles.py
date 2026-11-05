#!/usr/bin/env python3
"""Capture pinned Keycloak group role mappings and their effect on tokens."""
import json
import pathlib
import secrets

import oauth
from admin_realms import send_raw
from admin_roles import role_summary


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none'}, admin, expected=201)
    observations = {}
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm
    secret = secrets.token_urlsafe(40)

    def call(label, method, path, payload=None):
        response = send_raw(admin_base + path, method, json.dumps(payload).encode() if payload is not None else None, auth)
        observations[label] = role_summary(response, base, realm)
        return response

    def setup(method, path, payload=None):
        status, headers, body = send_raw(admin_base + path, method, json.dumps(payload).encode() if payload is not None else None, auth)
        assert status < 300, f'setup {method} {path}: {status}'
        return headers, body

    def claims(label):
        _, body = oauth.request(base + f'/realms/{realm}/protocol/openid-connect/token', [('grant_type', 'client_credentials'), ('client_id', 'member-app'), ('client_secret', secret)])
        token = json.loads(oauth.unbase64(json.loads(body)['access_token'].split('.')[1]))
        observations[label] = {
            'realm_access': sorted(name.replace(realm, '{realm}') for name in token.get('realm_access', {}).get('roles', [])),
            'resource_access': {client: sorted(entry['roles']) for client, entry in sorted(token.get('resource_access', {}).items())},
        }

    try:
        setup('POST', '/roles', {'name': 'parent-role'})
        setup('POST', '/roles', {'name': 'child-role'})
        app = setup('POST', '/clients', {'clientId': 'member-app', 'secret': secret, 'serviceAccountsEnabled': True, 'standardFlowEnabled': False})[0]['Location'].rsplit('/', 1)[1]
        setup('POST', f'/clients/{app}/roles', {'name': 'app-role'})
        parent = setup('POST', '/groups', {'name': 'parent'})[0]['Location'].rsplit('/', 1)[1]
        child = json.loads(setup('POST', f'/groups/{parent}/children', {'name': 'child'})[1])['id']
        member = json.loads(setup('GET', f'/clients/{app}/service-account-user')[1])['id']
        parent_role = json.loads(setup('GET', '/roles/parent-role')[1])
        child_role = json.loads(setup('GET', '/roles/child-role')[1])
        app_role = json.loads(setup('GET', f'/clients/{app}/roles/app-role')[1])
        call('realm/initial', 'GET', f'/groups/{parent}/role-mappings/realm')
        call('realm/add', 'POST', f'/groups/{parent}/role-mappings/realm', [{'id': parent_role['id'], 'name': 'parent-role'}])
        call('realm/add-child', 'POST', f'/groups/{child}/role-mappings/realm', [{'id': child_role['id'], 'name': 'child-role'}])
        call('realm/add-unknown-role', 'POST', f'/groups/{parent}/role-mappings/realm', [{'id': '00000000-0000-0000-0000-000000000000', 'name': 'missing'}])
        call('realm/unknown-group', 'GET', '/groups/00000000-0000-0000-0000-000000000000/role-mappings/realm')
        call('realm/after-add', 'GET', f'/groups/{parent}/role-mappings/realm')
        call('client/add', 'POST', f'/groups/{child}/role-mappings/clients/{app}', [{'id': app_role['id'], 'name': 'app-role'}])
        call('client/after-add', 'GET', f'/groups/{child}/role-mappings/clients/{app}')
        claims('token/before-join')
        setup('PUT', f'/users/{member}/groups/{child}')
        claims('token/member-of-child')
        call('user/direct-realm', 'GET', f'/users/{member}/role-mappings/realm')
        call('user/effective-realm', 'GET', f'/users/{member}/role-mappings/realm/composite')
        call('role/users', 'GET', '/roles/parent-role/users')
        call('group/full', 'GET', f'/groups/{parent}')
        observations['group/full']['realm_roles'] = json.loads(send_raw(admin_base + f'/groups/{parent}', 'GET', None, auth)[2]).get('realmRoles')
        call('realm/remove', 'DELETE', f'/groups/{parent}/role-mappings/realm', [{'id': parent_role['id'], 'name': 'parent-role'}])
        call('realm/after-remove', 'GET', f'/groups/{parent}/role-mappings/realm')
        claims('token/after-remove')
        call('group/delete-child', 'DELETE', f'/groups/{child}')
        claims('token/after-delete')
        call('role/delete-mapped', 'DELETE', '/roles/child-role')
        for observation in observations.values():
            if observation.get('names'):
                observation['names'] = [name.replace(realm, '{realm}') for name in observation['names']]
        baseline = pathlib.Path(__file__).with_name('group-role-observations.json')
        assert record or baseline.exists(), 'reference group role baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference group role case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference group role case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Group realm and client role mappings, their errors, inheritance from parent groups into tokens and effective user mappings, and removal through unmapping and group deletion; names and selected fields only.', 'normalization': 'The random realm name and base URL are replaced with placeholders.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference group role check failed: {detail}') from None
