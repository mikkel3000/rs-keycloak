#!/usr/bin/env python3
"""Capture pinned Keycloak group administration via public HTTP only."""
import json
import pathlib
import secrets

import oauth
from admin_realms import send_raw


def group_summary(response, base, realm):
    status, headers, body = response
    parsed = json.loads(body) if body and headers.get_content_type() == 'application/json' else None
    location = headers.get('Location')
    result = {
        'status': status,
        'location_pattern': location.replace(base, '{base}').replace(realm, '{realm}').rsplit('/', 1)[0] + '/{id}' if location else None,
        'empty_body': not body,
    }
    if isinstance(parsed, dict):
        result['body_fields'] = sorted(parsed)
        result['body'] = {key: parsed[key] for key in ['name', 'path', 'subGroupCount', 'error', 'error_description', 'errorMessage', 'count'] if key in parsed}
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
    groups = '/admin/realms/' + realm + '/groups'
    auth = {'Authorization': 'Bearer ' + admin}

    def call(label, method, path, payload=None, raw=None, token=admin):
        data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        headers = {'Authorization': 'Bearer ' + token} if token else {}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        response = send_raw(base + path, method, data, headers)
        observations[label] = group_summary(response, base, realm)
        return response

    try:
        call('list/initial', 'GET', groups)
        staff = call('create/top', 'POST', groups, {'name': 'staff'})[1]['Location'].rsplit('/', 1)[1]
        call('create/duplicate', 'POST', groups, {'name': 'staff'})
        call('create/missing-name', 'POST', groups, {})
        call('create/malformed-json', 'POST', groups, raw=b'{')
        call('create/no-token', 'POST', groups, {'name': 'x'}, token=None)
        call('create/child', 'POST', groups + '/' + staff + '/children', {'name': 'engineering'})
        call('create/child-duplicate', 'POST', groups + '/' + staff + '/children', {'name': 'engineering'})
        call('list/after-create', 'GET', groups)
        call('count', 'GET', groups + '/count')
        call('get/top', 'GET', groups + '/' + staff)
        call('get/unknown', 'GET', groups + '/00000000-0000-0000-0000-000000000000')
        children = json.loads(send_raw(base + groups + '/' + staff + '/children', 'GET', None, auth)[2])
        call('children', 'GET', groups + '/' + staff + '/children')
        call('get/child', 'GET', groups + '/' + children[0]['id'])
        created = send_raw(base + '/admin/realms/' + realm + '/users', 'POST', json.dumps({'username': 'member', 'enabled': True}).encode(), dict(auth, **{'Content-Type': 'application/json'}))
        user = '/admin/realms/' + realm + '/users/' + created[1]['Location'].rsplit('/', 1)[1]
        call('membership/initial', 'GET', user + '/groups')
        call('membership/join', 'PUT', user + '/groups/' + children[0]['id'])
        call('membership/join-repeat', 'PUT', user + '/groups/' + children[0]['id'])
        call('membership/join-unknown', 'PUT', user + '/groups/00000000-0000-0000-0000-000000000000')
        call('membership/after-join', 'GET', user + '/groups')
        call('members', 'GET', groups + '/' + children[0]['id'] + '/members')
        call('membership/leave', 'DELETE', user + '/groups/' + children[0]['id'])
        call('membership/after-leave', 'GET', user + '/groups')
        call('delete/top', 'DELETE', groups + '/' + staff)
        call('delete/repeat', 'DELETE', groups + '/' + staff)
        call('get/child-after-parent-delete', 'GET', groups + '/' + children[0]['id'])
        for observation in observations.values():
            for key, value in observation.get('body', {}).items():
                if isinstance(value, str):
                    observation['body'][key] = value.replace(realm, '{realm}')
        baseline = pathlib.Path(__file__).with_name('admin-group-observations.json')
        assert record or baseline.exists(), 'reference admin group baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference admin group case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference admin group case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Group and subgroup create, read, list, count, membership and delete through the admin API; names and selected fields only.', 'normalization': 'The random realm name and base URL are replaced with {realm} and {base}; created IDs are replaced with {id}.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference admin group check failed: {detail}') from None
