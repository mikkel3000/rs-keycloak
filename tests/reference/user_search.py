#!/usr/bin/env python3
"""Capture pinned Keycloak admin user search and count parameters."""
import json
import pathlib
import secrets
import urllib.parse

import oauth
from admin_realms import send_raw

USERS = [
    {'username': 'alice', 'email': 'alice@example.invalid', 'firstName': 'Alice', 'lastName': 'Smith', 'enabled': True, 'emailVerified': True},
    {'username': 'bob', 'email': 'bob@other.invalid', 'firstName': 'Bob', 'lastName': 'Smithson', 'enabled': False, 'emailVerified': False},
    {'username': 'carol', 'email': 'carol@example.invalid', 'firstName': 'Carol', 'lastName': 'Jones', 'enabled': True, 'emailVerified': False},
    {'username': 'smith-admin', 'enabled': True},
]
QUERIES = [
    ('search/plain', {'search': 'smith'}),
    ('search/upper', {'search': 'SMITH'}),
    ('search/email-domain', {'search': 'example.invalid'}),
    ('search/prefix-star', {'search': 'smi*'}),
    ('search/exact-quoted', {'search': '"alice"'}),
    ('search/first-name', {'search': 'carol'}),
    ('search/empty', {'search': ''}),
    ('search/paged', {'search': 'smith', 'first': '1', 'max': '1'}),
    ('email/contains', {'email': 'example'}),
    ('email/exact', {'email': 'alice@example.invalid', 'exact': 'true'}),
    ('email/exact-partial', {'email': 'alice', 'exact': 'true'}),
    ('first-name/contains', {'firstName': 'ali'}),
    ('last-name/contains', {'lastName': 'smith'}),
    ('last-name/exact', {'lastName': 'smith', 'exact': 'true'}),
    ('combined/and', {'lastName': 'smith', 'email': 'other'}),
    ('enabled/false', {'enabled': 'false'}),
    ('enabled/true', {'enabled': 'true'}),
    ('email-verified/true', {'emailVerified': 'true'}),
    ('search-with-username', {'search': 'alice', 'username': 'bob'}),
    ('brief', {'search': 'alice', 'briefRepresentation': 'true'}),
]
COUNTS = [
    ('count/all', {}),
    ('count/search', {'search': 'smith'}),
    ('count/email', {'email': 'example'}),
    ('count/last-name', {'lastName': 'smith'}),
    ('count/enabled', {'enabled': 'false'}),
    ('count/email-verified', {'emailVerified': 'true'}),
]


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True}, admin, expected=201)
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm
    observations = {}
    try:
        for user in USERS:
            assert send_raw(admin_base + '/users', 'POST', json.dumps(user).encode(), auth)[0] == 201
        for label, params in QUERIES:
            status, _, body = send_raw(admin_base + '/users?' + urllib.parse.urlencode(params), 'GET', None, auth)
            parsed = json.loads(body)
            observations[label] = {'status': status, 'usernames': [item['username'] for item in parsed] if isinstance(parsed, list) else None}
            if label == 'brief':
                observations[label]['fields'] = sorted(parsed[0])
        for label, params in COUNTS:
            status, _, body = send_raw(admin_base + '/users/count?' + urllib.parse.urlencode(params), 'GET', None, auth)
            observations[label] = {'status': status, 'value': json.loads(body)}
        baseline = pathlib.Path(__file__).with_name('user-search-observations.json')
        assert record or baseline.exists(), 'reference user search baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations == expected, 'reference user search cases changed'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Admin user search by search, email, firstName, lastName, enabled and emailVerified, with exact, paging and brief forms, and the matching counts; usernames in response order only.', 'normalization': 'None needed: only fixture usernames are kept.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference user search check failed: {detail}') from None
