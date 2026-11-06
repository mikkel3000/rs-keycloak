#!/usr/bin/env python3
"""Capture pinned Keycloak combined role mappings for users and groups."""
import json
import pathlib
import secrets

import oauth
from admin_realms import send_raw


def shape(response, realm):
    status, headers, body = response
    parsed = json.loads(body) if body and headers.get_content_type() == 'application/json' else None
    result = {'status': status}
    if isinstance(parsed, dict) and ('realmMappings' in parsed or 'clientMappings' in parsed or not parsed):
        result['fields'] = sorted(parsed)
        result['realm'] = sorted(role['name'].replace(realm, '{realm}') for role in parsed.get('realmMappings', []))
        result['clients'] = {
            name: {'fields': sorted(entry), 'client': entry.get('client'), 'id_is_uuid': len(entry.get('id', '')) == 36, 'mappings': sorted(role['name'] for role in entry.get('mappings', []))}
            for name, entry in sorted(parsed.get('clientMappings', {}).items())
        }
        result['role_fields'] = sorted({field for role in parsed.get('realmMappings', []) for field in role})
    elif isinstance(parsed, dict):
        result['error'] = parsed.get('error')
    return result


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True}, admin, expected=201)
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm
    observations = {}

    def setup(method, path, payload=None):
        status, headers, body = send_raw(admin_base + path, method, json.dumps(payload).encode() if payload is not None else None, auth)
        assert status < 300, f'setup {method} {path}: {status}'
        return headers, body

    try:
        setup('POST', '/roles', {'name': 'mapped'})
        app = setup('POST', '/clients', {'clientId': 'mapped-app', 'publicClient': True})[0]['Location'].rsplit('/', 1)[1]
        setup('POST', f'/clients/{app}/roles', {'name': 'app-role'})
        user = setup('POST', '/users', {'username': 'mapped-user', 'enabled': True})[0]['Location'].rsplit('/', 1)[1]
        group = setup('POST', '/groups', {'name': 'mapped-group'})[0]['Location'].rsplit('/', 1)[1]
        mapped = json.loads(setup('GET', '/roles/mapped')[1])
        app_role = json.loads(setup('GET', f'/clients/{app}/roles/app-role')[1])
        observations['user/initial'] = shape(send_raw(admin_base + f'/users/{user}/role-mappings', 'GET', None, auth), realm)
        observations['group/initial'] = shape(send_raw(admin_base + f'/groups/{group}/role-mappings', 'GET', None, auth), realm)
        for holder in (f'/users/{user}', f'/groups/{group}'):
            setup('POST', holder + '/role-mappings/realm', [{'id': mapped['id'], 'name': 'mapped'}])
            setup('POST', holder + f'/role-mappings/clients/{app}', [{'id': app_role['id'], 'name': 'app-role'}])
        observations['user/mapped'] = shape(send_raw(admin_base + f'/users/{user}/role-mappings', 'GET', None, auth), realm)
        observations['group/mapped'] = shape(send_raw(admin_base + f'/groups/{group}/role-mappings', 'GET', None, auth), realm)
        observations['user/unknown'] = shape(send_raw(admin_base + '/users/00000000-0000-0000-0000-000000000000/role-mappings', 'GET', None, auth), realm)
        observations['group/unknown'] = shape(send_raw(admin_base + '/groups/00000000-0000-0000-0000-000000000000/role-mappings', 'GET', None, auth), realm)
        baseline = pathlib.Path(__file__).with_name('role-mapping-observations.json')
        assert record or baseline.exists(), 'reference role mapping baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations == expected, 'reference role mapping cases changed'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Combined role mappings of a user and a group before and after realm and client mappings, and of unknown holders; shape and names only.', 'normalization': 'The random realm name is replaced with a placeholder.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference role mapping check failed: {detail}') from None
