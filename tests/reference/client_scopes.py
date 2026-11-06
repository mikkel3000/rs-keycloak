#!/usr/bin/env python3
"""Capture pinned Keycloak built-in client scopes and a client's scope lists."""
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

    def get(path):
        status, _, body = send_raw(admin_base + path, 'GET', None, auth)
        return status, json.loads(body) if body else None

    def names(items):
        return sorted(item['name'] for item in items)

    try:
        status, scopes = get('/client-scopes')
        observations['client-scopes'] = {
            'status': status,
            'fields': sorted({field for item in scopes for field in item}),
            'scopes': sorted([item['name'], item['protocol'], item.get('attributes', {}).get('include.in.token.scope'), item.get('attributes', {}).get('display.on.consent.screen')] for item in scopes),
        }
        profile = next(item for item in scopes if item['name'] == 'profile')
        status, one = get(f"/client-scopes/{profile['id']}")
        observations['client-scope/profile'] = {'status': status, 'fields': sorted(one), 'mappers': sorted(mapper['name'] for mapper in one.get('protocolMappers', []))}
        observations['client-scope/unknown'] = dict(zip(('status', 'body'), get('/client-scopes/00000000-0000-0000-0000-000000000000')))
        status, defaults = get('/default-default-client-scopes')
        observations['realm/default-default'] = {'status': status, 'names': names(defaults), 'fields': sorted({field for item in defaults for field in item})}
        status, optional = get('/default-optional-client-scopes')
        observations['realm/default-optional'] = {'status': status, 'names': names(optional)}
        client = send_raw(admin_base + '/clients', 'POST', json.dumps({'clientId': 'scoped-app', 'publicClient': True}).encode(), auth)[1]['Location'].rsplit('/', 1)[1]
        status, defaults = get(f'/clients/{client}/default-client-scopes')
        observations['client/default'] = {'status': status, 'names': names(defaults), 'fields': sorted({field for item in defaults for field in item})}
        status, optional = get(f'/clients/{client}/optional-client-scopes')
        observations['client/optional'] = {'status': status, 'names': names(optional)}
        status, body = get('/clients/00000000-0000-0000-0000-000000000000/default-client-scopes')
        observations['client/unknown'] = {'status': status, 'body': body}
        status, representation = get(f'/clients/{client}')
        observations['client/representation'] = {'default': sorted(representation.get('defaultClientScopes', [])), 'optional': sorted(representation.get('optionalClientScopes', []))}
        baseline = pathlib.Path(__file__).with_name('client-scope-observations.json')
        assert record or baseline.exists(), 'reference client scope baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference client scope case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference client scope case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Built-in client scopes of a new realm, one scope read, the realm default scope lists, and a new client default and optional scopes; names and selected fields only.', 'normalization': 'No identifiers are kept.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)
