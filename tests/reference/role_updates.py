#!/usr/bin/env python3
"""Capture pinned Keycloak role updates and the roles-by-id endpoints."""
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
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True}, admin, expected=201)
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm
    observations = {}

    def call(label, method, path, payload=None, raw=None):
        data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        response = send_raw(admin_base + path, method, data, auth)
        observations[label] = role_summary(response, base, realm)
        return response

    try:
        for name in ('editor', 'viewer', 'child'):
            assert send_raw(admin_base + '/roles', 'POST', json.dumps({'name': name, 'description': 'Old'}).encode(), auth)[0] == 201
        app = send_raw(admin_base + '/clients', 'POST', json.dumps({'clientId': 'role-app', 'publicClient': True}).encode(), auth)[1]['Location'].rsplit('/', 1)[1]
        assert send_raw(admin_base + f'/clients/{app}/roles', 'POST', json.dumps({'name': 'app-role'}).encode(), auth)[0] == 201
        editor = json.loads(send_raw(admin_base + '/roles/editor', 'GET', None, auth)[2])
        child = json.loads(send_raw(admin_base + '/roles/child', 'GET', None, auth)[2])
        app_role = json.loads(send_raw(admin_base + f'/clients/{app}/roles/app-role', 'GET', None, auth)[2])
        call('update/description', 'PUT', '/roles/editor', {'name': 'editor', 'description': 'New'})
        call('get/after-description', 'GET', '/roles/editor')
        call('update/no-name', 'PUT', '/roles/editor', {'description': 'Nameless'})
        call('get/after-no-name', 'GET', '/roles/editor')
        call('update/rename', 'PUT', '/roles/editor', {'name': 'writer'})
        call('get/old-name', 'GET', '/roles/editor')
        call('get/new-name', 'GET', '/roles/writer')
        call('update/rename-taken', 'PUT', '/roles/writer', {'name': 'viewer'})
        call('update/unknown', 'PUT', '/roles/missing', {'name': 'missing'})
        call('update/malformed', 'PUT', '/roles/writer', raw=b'{')
        call('update/client-role', 'PUT', f'/clients/{app}/roles/app-role', {'name': 'app-role', 'description': 'Client'})
        call('get/client-role', 'GET', f'/clients/{app}/roles/app-role')
        call('by-id/get', 'GET', f"/roles-by-id/{editor['id']}")
        call('by-id/get-client-role', 'GET', f"/roles-by-id/{app_role['id']}")
        call('by-id/unknown', 'GET', '/roles-by-id/00000000-0000-0000-0000-000000000000')
        call('by-id/update', 'PUT', f"/roles-by-id/{editor['id']}", {'name': 'author', 'description': 'By id'})
        call('by-id/after-update', 'GET', f"/roles-by-id/{editor['id']}")
        call('by-id/add-composite', 'POST', f"/roles-by-id/{editor['id']}/composites", [{'id': child['id'], 'name': 'child'}])
        call('by-id/composites', 'GET', f"/roles-by-id/{editor['id']}/composites")
        call('by-id/remove-composite', 'DELETE', f"/roles-by-id/{editor['id']}/composites", [{'id': child['id'], 'name': 'child'}])
        call('by-id/delete', 'DELETE', f"/roles-by-id/{editor['id']}")
        call('by-id/after-delete', 'GET', f"/roles-by-id/{editor['id']}")
        for observation in observations.values():
            if observation.get('names'):
                observation['names'] = [name.replace(realm, '{realm}') for name in observation['names']]
        baseline = pathlib.Path(__file__).with_name('role-update-observations.json')
        assert record or baseline.exists(), 'reference role update baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations == expected, 'reference role update cases changed'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Realm and client role updates by name, renames and their conflicts, and roles-by-id read, update, composites and delete; names and selected fields only.', 'normalization': 'The random realm name and base URL are replaced with placeholders.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference role update check failed: {detail}') from None
