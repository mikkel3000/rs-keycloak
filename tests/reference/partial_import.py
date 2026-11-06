#!/usr/bin/env python3
"""Capture pinned Keycloak realm partial import through the admin API."""
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
        'roles': {'realm': [{'name': 'imported-role', 'description': 'From import'}]},
        'clients': [{'clientId': 'imported-app', 'publicClient': True, 'redirectUris': ['https://app.example.invalid/cb']}],
        'users': [{'username': 'imported-user', 'enabled': True, 'email': 'imported@example.invalid'}],
    }

    def summary(response):
        status, _, body = response
        parsed = json.loads(body) if body else None
        result = {'status': status}
        if isinstance(parsed, dict) and 'results' in parsed:
            result |= {'added': parsed.get('added'), 'skipped': parsed.get('skipped'), 'overwritten': parsed.get('overwritten'), 'fields': sorted(parsed), 'result_fields': sorted({field for item in parsed['results'] for field in item}), 'results': sorted([item['action'], item['resourceType'], item['resourceName']] for item in parsed['results'])}
        elif isinstance(parsed, dict):
            result['body'] = parsed
        return result

    def get(path):
        status, _, body = send_raw(admin_base + path, 'GET', None, auth)
        return json.loads(body) if status == 200 else status

    try:
        observations['import/fail'] = summary(send_raw(admin_base + '/partialImport', 'POST', json.dumps(payload | {'ifResourceExists': 'FAIL'}).encode(), auth))
        users = get('/users?username=imported-user&exact=true')
        assert users, f"import created no user: {observations['import/fail']}"
        user = users[0]
        observations['after/user'] = {'email': user.get('email'), 'realm_roles': sorted(role['name'].replace(realm, '{realm}') for role in get(f"/users/{user['id']}/role-mappings/realm"))}
        observations['after/role'] = {'description': get('/roles/imported-role').get('description')}
        client = get('/clients?clientId=imported-app')[0]
        observations['after/client'] = {'public': client.get('publicClient'), 'redirects': client.get('redirectUris')}
        observations['import/fail-again'] = summary(send_raw(admin_base + '/partialImport', 'POST', json.dumps(payload | {'ifResourceExists': 'FAIL'}).encode(), auth))
        observations['import/skip'] = summary(send_raw(admin_base + '/partialImport', 'POST', json.dumps(payload | {'ifResourceExists': 'SKIP'}).encode(), auth))
        changed = json.loads(json.dumps(payload))
        changed['roles']['realm'][0]['description'] = 'Overwritten'
        changed['users'][0]['email'] = 'overwritten@example.invalid'
        observations['import/overwrite'] = summary(send_raw(admin_base + '/partialImport', 'POST', json.dumps(changed | {'ifResourceExists': 'OVERWRITE'}).encode(), auth))
        user = get('/users?username=imported-user&exact=true')[0]
        observations['after-overwrite'] = {'role_description': get('/roles/imported-role').get('description'), 'email': user.get('email')}
        observations['import/malformed'] = summary(send_raw(admin_base + '/partialImport', 'POST', b'{', auth))
        observations['import/empty'] = summary(send_raw(admin_base + '/partialImport', 'POST', b'{}', auth))
        # The reference fails on groups given without a path; recorded, not followed.
        observations['import/group-without-path'] = summary(send_raw(admin_base + '/partialImport', 'POST', json.dumps({'groups': [{'name': 'imported-group'}]}).encode(), auth))
        baseline = pathlib.Path(__file__).with_name('partial-import-observations.json')
        assert record or baseline.exists(), 'reference partial import baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference partial import case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference partial import case changed: {label}: {observations[label]}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Partial import of realm roles, clients and users with FAIL, SKIP and OVERWRITE policies, the imported state, and malformed and empty bodies; names, counts and selected values only.', 'normalization': 'The random realm name is replaced with a placeholder.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)
