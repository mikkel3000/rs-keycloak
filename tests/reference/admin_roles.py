#!/usr/bin/env python3
"""Capture pinned Keycloak realm role administration via public HTTP only."""
import json
import pathlib
import secrets

import oauth
from admin_realms import send_raw


def role_summary(response, base, realm):
    status, headers, body = response
    parsed = json.loads(body) if body and headers.get_content_type() == 'application/json' else None
    location = headers.get('Location')
    result = {
        'status': status,
        'location': location.replace(base, '{base}').replace(realm, '{realm}') if location else None,
        'empty_body': not body,
    }
    if isinstance(parsed, dict):
        result['body_fields'] = sorted(parsed)
        result['body'] = {key: parsed[key] for key in ['name', 'description', 'composite', 'clientRole', 'error', 'error_description', 'errorMessage'] if key in parsed}
    elif isinstance(parsed, list):
        result['names'] = sorted(item.get('name') or item.get('username') for item in parsed)
        result['item_fields'] = sorted({field for item in parsed for field in item})
    return result


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True}, admin, expected=201)
    observations = {}
    roles = '/admin/realms/' + realm + '/roles'
    users = '/admin/realms/' + realm + '/users'

    def call(label, method, path, payload=None, raw=None, token=admin):
        data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        headers = {'Authorization': 'Bearer ' + token} if token else {}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        response = send_raw(base + path, method, data, headers)
        observations[label] = role_summary(response, base, realm)
        return response

    try:
        call('list/defaults', 'GET', roles)
        call('create/success', 'POST', roles, {'name': 'reader', 'description': 'Reads things'})
        call('create/second', 'POST', roles, {'name': 'writer'})
        call('create/duplicate', 'POST', roles, {'name': 'reader'})
        call('create/missing-name', 'POST', roles, {'description': 'x'})
        call('create/malformed-json', 'POST', roles, raw=b'{')
        call('create/no-token', 'POST', roles, {'name': 'x'}, token=None)
        call('get/success', 'GET', roles + '/reader')
        call('get/unknown', 'GET', roles + '/missing-role')
        call('list/after-create', 'GET', roles)
        created = send_raw(base + users, 'POST', json.dumps({'username': 'role-user', 'enabled': True}).encode(), {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'})
        user_id = created[1]['Location'].rsplit('/', 1)[1]
        mappings = users + '/' + user_id + '/role-mappings/realm'
        call('mappings/initial', 'GET', mappings)
        reader = json.loads(send_raw(base + roles + '/reader', 'GET', None, {'Authorization': 'Bearer ' + admin})[2])
        call('mappings/add', 'POST', mappings, [{'id': reader['id'], 'name': 'reader'}])
        call('mappings/add-repeat', 'POST', mappings, [{'id': reader['id'], 'name': 'reader'}])
        call('mappings/add-unknown', 'POST', mappings, [{'id': '00000000-0000-0000-0000-000000000000', 'name': 'missing-role'}])
        call('mappings/after-add', 'GET', mappings)
        call('role-users', 'GET', roles + '/reader/users')
        call('mappings/remove', 'DELETE', mappings, [{'id': reader['id'], 'name': 'reader'}])
        call('mappings/after-remove', 'GET', mappings)
        call('delete/success', 'DELETE', roles + '/writer')
        call('delete/repeat', 'DELETE', roles + '/writer')
        for observation in observations.values():
            for key, value in observation.get('body', {}).items():
                if isinstance(value, str):
                    observation['body'][key] = value.replace(realm, '{realm}')
            if observation.get('names'):
                observation['names'] = [name.replace(realm, '{realm}') for name in observation['names']]
        baseline = pathlib.Path(__file__).with_name('admin-role-observations.json')
        assert record or baseline.exists(), 'reference admin role baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference admin role case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference admin role case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Realm role create, read, list and delete, and user realm role mappings, through the admin API; names and selected fields only.', 'normalization': 'The random realm name and base URL are replaced with {realm} and {base}.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference admin role check failed: {detail}') from None
