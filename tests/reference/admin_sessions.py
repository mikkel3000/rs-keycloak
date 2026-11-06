#!/usr/bin/env python3
"""Capture pinned Keycloak admin session listing and ending."""
import json
import pathlib
import secrets

import oauth
from admin_realms import send_raw
from tokens import login, send


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    callback = base + '/callback'
    clients = [{'clientId': name, 'publicClient': True, 'redirectUris': [callback]} for name in ('first-app', 'second-app')]
    user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': clients, 'users': [user]}, admin, expected=201)
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm
    issuer = base + '/realms/' + realm
    observations = {}

    def get(path):
        status, headers, body = send_raw(admin_base + path, 'GET', None, auth)
        return status, (json.loads(body) if body else None)

    def shape(label, status, parsed, ids):
        result = {'status': status}
        if isinstance(parsed, list):
            result['count'] = len(parsed)
            result['item_fields'] = sorted({field for item in parsed for field in item})
            result['clients'] = sorted(sorted(item.get('clients', {}).values()) for item in parsed)
            result['usernames'] = sorted(item.get('username') for item in parsed if 'username' in item)
            result['stats'] = sorted([item.get('clientId'), item.get('active'), item.get('offline')] for item in parsed if 'active' in item)
        elif isinstance(parsed, dict):
            result['body'] = parsed if label in ('client/session-count', 'logout-all') else {key: parsed[key] for key in ('error', 'errorMessage') if key in parsed}
        observations[label] = result

    def refresh(label, tokens, client):
        status, _, body = send(issuer + '/protocol/openid-connect/token', [('grant_type', 'refresh_token'), ('client_id', client), ('refresh_token', tokens['refresh_token'])])
        observations[label] = {'status': status, 'error': json.loads(body).get('error')}

    try:
        user_id = json.loads(send_raw(admin_base + '/users?username=reference-user&exact=true', 'GET', None, auth)[2])[0]['id']
        ids = {item['clientId']: item['id'] for item in json.loads(send_raw(admin_base + '/clients', 'GET', None, auth)[2])}
        first, browser = login(issuer, 'first-app', None, password)
        second, _ = login(issuer, 'second-app', None, password, browser=browser)
        other, _ = login(issuer, 'first-app', None, password)
        shape('user/sessions', *get(f'/users/{user_id}/sessions'), ids)
        shape('client/user-sessions', *get(f"/clients/{ids['first-app']}/user-sessions"), ids)
        shape('client/session-count', *get(f"/clients/{ids['first-app']}/session-count"), ids)
        shape('client-session-stats', *get('/client-session-stats'), ids)
        sessions = json.loads(send_raw(admin_base + f'/users/{user_id}/sessions', 'GET', None, auth)[2])
        shared = next(item['id'] for item in sessions if len(item['clients']) == 2)
        status, _, body = send_raw(admin_base + f'/sessions/{shared}', 'DELETE', None, auth)
        observations['delete-session'] = {'status': status, 'empty_body': not body}
        refresh('refresh/deleted-first', first, 'first-app')
        refresh('refresh/deleted-second', second, 'second-app')
        refresh('refresh/other-session', other, 'first-app')
        status, _, body = send_raw(admin_base + '/sessions/00000000-0000-0000-0000-000000000000', 'DELETE', None, auth)
        observations['delete-session/unknown'] = {'status': status, 'body': json.loads(body) if body else None}
        status, _, body = send_raw(admin_base + f'/users/{user_id}/logout', 'POST', None, auth)
        observations['user-logout'] = {'status': status, 'empty_body': not body}
        refresh('refresh/after-user-logout', other, 'first-app')
        shape('user/sessions-after', *get(f'/users/{user_id}/sessions'), ids)
        status, _, body = send_raw(admin_base + '/users/00000000-0000-0000-0000-000000000000/logout', 'POST', None, auth)
        observations['user-logout/unknown'] = {'status': status, 'body': json.loads(body) if body else None}
        again, _ = login(issuer, 'first-app', None, password)
        status, _, body = send_raw(admin_base + '/logout-all', 'POST', None, auth)
        shape('logout-all', status, json.loads(body) if body else None, ids)
        refresh('refresh/after-logout-all', again, 'first-app')
        baseline = pathlib.Path(__file__).with_name('admin-session-observations.json')
        assert record or baseline.exists(), 'reference admin session baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference admin session case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference admin session case changed: {label}: {observations[label]}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Admin listing of user and client sessions, session counts and client session stats, and ending one session, all sessions of a user and every realm session, with refresh checks; shapes and selected values only.', 'normalization': 'No identifiers are kept; clients are named by clientId.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference admin session check failed: {detail}') from None
