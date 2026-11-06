#!/usr/bin/env python3
"""Capture pinned Keycloak group renames and moves."""
import json
import pathlib
import secrets

import oauth
from admin_groups import group_summary
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

    def call(label, method, path, payload=None, raw=None):
        data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        response = send_raw(admin_base + path, method, data, auth)
        observations[label] = group_summary(response, base, realm)
        return response

    def create(path, name):
        status, headers, body = send_raw(admin_base + path, 'POST', json.dumps({'name': name}).encode(), auth)
        assert status == 201, f'setup {name}: {status}'
        return headers['Location'].rsplit('/', 1)[1] if headers.get('Location') else json.loads(body)['id']

    try:
        a = create('/groups', 'a')
        create('/groups', 'b')
        child = create(f'/groups/{a}/children', 'child')
        create(f'/groups/{a}/children', 'sibling')
        loose = create('/groups', 'loose')
        call('rename', 'PUT', f'/groups/{a}', {'name': 'renamed'})
        call('get/after-rename', 'GET', f'/groups/{a}')
        call('get/child-path', 'GET', f'/groups/{child}')
        call('rename/top-level-taken', 'PUT', f'/groups/{a}', {'name': 'b'})
        call('rename/sibling-taken', 'PUT', f'/groups/{child}', {'name': 'sibling'})
        call('rename/no-name', 'PUT', f'/groups/{a}', {})
        call('rename/unknown', 'PUT', '/groups/00000000-0000-0000-0000-000000000000', {'name': 'x'})
        call('rename/malformed', 'PUT', f'/groups/{a}', raw=b'{')
        call('rename/slash', 'PUT', f'/groups/{a}', {'name': 'x/y'})
        call('move/into-parent', 'POST', f'/groups/{a}/children', {'id': loose, 'name': 'loose'})
        call('get/after-move', 'GET', f'/groups/{loose}')
        call('list/top-level-after-move', 'GET', '/groups')
        call('move/to-top', 'POST', '/groups', {'id': child, 'name': 'child'})
        call('get/after-move-top', 'GET', f'/groups/{child}')
        call('move/into-self', 'POST', f'/groups/{a}/children', {'id': a, 'name': 'renamed'})
        call('move/into-descendant', 'POST', f'/groups/{loose}/children', {'id': a, 'name': 'renamed'})
        baseline = pathlib.Path(__file__).with_name('group-update-observations.json')
        assert record or baseline.exists(), 'reference group update baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations == expected, 'reference group update cases changed'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Group renames with their name conflicts and errors, and moves between parents and to the top level, including into itself and a descendant; names, paths and selected fields only.', 'normalization': 'The random realm name and base URL are replaced with placeholders.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference group update check failed: {detail}') from None
