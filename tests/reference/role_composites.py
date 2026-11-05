#!/usr/bin/env python3
"""Capture pinned Keycloak composite role editing and its effect on tokens."""
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
        _, body = oauth.request(base + f'/realms/{realm}/protocol/openid-connect/token', [('grant_type', 'client_credentials'), ('client_id', 'holder-app'), ('client_secret', secret)])
        token = json.loads(oauth.unbase64(json.loads(body)['access_token'].split('.')[1]))
        observations[label] = {
            'realm_access': sorted(name.replace(realm, '{realm}') for name in token.get('realm_access', {}).get('roles', [])),
            'resource_access': sorted(token.get('resource_access', {}).get('holder-app', {}).get('roles', [])),
        }

    try:
        for name in ('parent', 'child', 'grandchild'):
            setup('POST', '/roles', {'name': name})
        app = setup('POST', '/clients', {'clientId': 'holder-app', 'secret': secret, 'serviceAccountsEnabled': True, 'standardFlowEnabled': False})[0]['Location'].rsplit('/', 1)[1]
        setup('POST', f'/clients/{app}/roles', {'name': 'app-child'})
        setup('POST', f'/clients/{app}/roles', {'name': 'app-parent'})
        roles = {name: json.loads(setup('GET', f'/roles/{name}')[1]) for name in ('parent', 'child', 'grandchild')}
        app_child = json.loads(setup('GET', f'/clients/{app}/roles/app-child')[1])
        holder = json.loads(setup('GET', f'/clients/{app}/service-account-user')[1])['id']
        ref = lambda name: [{'id': roles[name]['id'], 'name': name}]
        setup('POST', f'/users/{holder}/role-mappings/realm', ref('parent'))
        claims('token/before')
        call('add/realm-child', 'POST', '/roles/parent/composites', ref('child'))
        call('add/client-child', 'POST', '/roles/parent/composites', [{'id': app_child['id'], 'name': 'app-child'}])
        call('add/grandchild', 'POST', '/roles/child/composites', ref('grandchild'))
        call('add/repeat', 'POST', '/roles/parent/composites', ref('child'))
        call('add/unknown-role', 'POST', '/roles/parent/composites', [{'id': '00000000-0000-0000-0000-000000000000', 'name': 'missing'}])
        call('add/unknown-parent', 'POST', '/roles/missing/composites', ref('child'))
        call('add/self', 'POST', '/roles/parent/composites', ref('parent'))
        call('add/cycle', 'POST', '/roles/grandchild/composites', ref('parent'))
        call('add/client-parent', 'POST', f'/clients/{app}/roles/app-parent/composites', ref('child'))
        call('add/malformed', 'POST', '/roles/parent/composites', {'name': 'child'})
        call('get/parent', 'GET', '/roles/parent')
        observations['get/parent']['composite'] = json.loads(send_raw(admin_base + '/roles/parent', 'GET', None, auth)[2]).get('composite')
        call('list/composites', 'GET', '/roles/parent/composites')
        call('list/realm-composites', 'GET', '/roles/parent/composites/realm')
        call('list/client-composites', 'GET', f'/roles/parent/composites/clients/{app}')
        call('user/effective', 'GET', f'/users/{holder}/role-mappings/realm/composite')
        claims('token/after-add')
        call('remove/child', 'DELETE', '/roles/parent/composites', ref('child'))
        call('list/after-remove', 'GET', '/roles/parent/composites')
        claims('token/after-remove')
        call('remove/last', 'DELETE', '/roles/parent/composites', [{'id': app_child['id'], 'name': 'app-child'}])
        observations['get/after-remove-last'] = {'composite': json.loads(send_raw(admin_base + '/roles/parent', 'GET', None, auth)[2]).get('composite')}
        call('create/composite', 'POST', '/roles', {'name': 'born-composite', 'composite': True, 'composites': {'realm': ['child']}})
        call('get/born-composite', 'GET', '/roles/born-composite/composites')
        for observation in observations.values():
            if observation.get('names'):
                observation['names'] = [name.replace(realm, '{realm}') for name in observation['names']]
        baseline = pathlib.Path(__file__).with_name('role-composite-observations.json')
        assert record or baseline.exists(), 'reference role composite baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference role composite case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference role composite case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Adding and removing realm and client role composites, their errors, cycles, listings by container, creation with composites, and effective roles in tokens; names and selected fields only.', 'normalization': 'The random realm name and base URL are replaced with placeholders.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference role composite check failed: {detail}') from None
