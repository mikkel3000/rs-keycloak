#!/usr/bin/env python3
"""Capture pinned Keycloak client role administration and token claims."""
import json
import pathlib
import secrets

import oauth
from admin_realms import send_raw
from admin_roles import role_summary
from tokens import login


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    callback = base + '/callback'
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [{'clientId': 'roles-app', 'publicClient': True, 'redirectUris': [callback]}]}, admin, expected=201)
    oauth.request(base + '/admin/realms/' + realm + '/users', {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}, admin, expected=201)
    observations = {}
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm

    def call(label, method, path, payload=None, raw=None):
        data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        response = send_raw(admin_base + path, method, data, auth)
        observations[label] = role_summary(response, base, realm)
        return response

    try:
        clients = json.loads(send_raw(admin_base + '/clients', 'GET', None, auth)[2])
        ids = {client['clientId']: client['id'] for client in clients}
        app = ids['roles-app']
        call('account/roles', 'GET', f"/clients/{ids['account']}/roles")
        call('default-role/composites', 'GET', f'/roles/default-roles-{realm}/composites')
        call('create/success', 'POST', f'/clients/{app}/roles', {'name': 'editor', 'description': 'Edits'})
        observations['create/success']['location'] = (observations['create/success']['location'] or '').replace(app, '{client}')
        call('create/duplicate', 'POST', f'/clients/{app}/roles', {'name': 'editor'})
        call('create/missing-name', 'POST', f'/clients/{app}/roles', {})
        call('create/unknown-client', 'POST', '/clients/00000000-0000-0000-0000-000000000000/roles', {'name': 'x'})
        call('list', 'GET', f'/clients/{app}/roles')
        editor = json.loads(call('get', 'GET', f'/clients/{app}/roles/editor')[2])
        observations['get']['client_role'] = editor.get('clientRole')
        observations['get']['container_is_client'] = editor.get('containerId') == app
        call('get/unknown', 'GET', f'/clients/{app}/roles/missing')
        users = json.loads(send_raw(admin_base + '/users?username=reference-user&exact=true', 'GET', None, auth)[2])
        mappings = f"/users/{users[0]['id']}/role-mappings/clients/{app}"
        call('mappings/initial', 'GET', mappings)
        call('mappings/add', 'POST', mappings, [{'id': editor['id'], 'name': 'editor'}])
        call('mappings/add-unknown', 'POST', mappings, [{'id': '00000000-0000-0000-0000-000000000000', 'name': 'missing'}])
        call('mappings/after-add', 'GET', mappings)
        tokens, _ = login(base + '/realms/' + realm, 'roles-app', None, password)
        claims = json.loads(oauth.unbase64(tokens['access_token'].split('.')[1]))
        observations['token/resource_access'] = {client: sorted(entry.get('roles', [])) for client, entry in sorted(claims.get('resource_access', {}).items())}
        observations['token/aud'] = {'aud': claims.get('aud')}
        call('mappings/remove', 'DELETE', mappings, [{'id': editor['id'], 'name': 'editor'}])
        call('mappings/after-remove', 'GET', mappings)
        call('delete', 'DELETE', f'/clients/{app}/roles/editor')
        call('delete/repeat', 'DELETE', f'/clients/{app}/roles/editor')
        for observation in observations.values():
            if observation.get('names'):
                observation['names'] = [name.replace(realm, '{realm}') for name in observation['names']]
        baseline = pathlib.Path(__file__).with_name('client-role-observations.json')
        assert record or baseline.exists(), 'reference client role baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference client role case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference client role case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Client role create, read, list and delete, user client-role mappings, the account client roles and default-role composites, and resource_access in tokens; names and selected fields only.', 'normalization': 'The random realm name, base URL and client ID are replaced with placeholders.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference client role check failed: {detail}') from None
