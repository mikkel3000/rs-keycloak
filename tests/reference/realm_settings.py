#!/usr/bin/env python3
"""Capture pinned Keycloak realm displayName and accessTokenLifespan."""
import json
import pathlib
import secrets
import urllib.parse

import oauth
from admin_realms import send_raw
from tokens import login, send


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password, secret = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30), secrets.token_urlsafe(40)
    callback = base + '/callback'
    clients = [{'clientId': 'user-app', 'publicClient': True, 'redirectUris': [callback]}, {'clientId': 'service-app', 'secret': secret, 'serviceAccountsEnabled': True, 'standardFlowEnabled': False}]
    user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': clients, 'users': [user]}, admin, expected=201)
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm
    issuer = base + '/realms/' + realm
    observations = {}

    def realm_fields(label):
        parsed = json.loads(send_raw(admin_base, 'GET', None, auth)[2])
        observations[label] = {key: parsed.get(key) for key in ('displayName', 'displayNameHtml', 'accessTokenLifespan', 'accessTokenLifespanForImplicitFlow', 'ssoSessionIdleTimeout', 'ssoSessionMaxLifespan')}

    def lifetimes(label):
        status, _, body = send(issuer + '/protocol/openid-connect/token', [('grant_type', 'client_credentials'), ('client_id', 'service-app'), ('client_secret', secret)])
        service = json.loads(body)
        claims = json.loads(oauth.unbase64(service['access_token'].split('.')[1]))
        tokens, _ = login(issuer, 'user-app', None, password)
        access = json.loads(oauth.unbase64(tokens['access_token'].split('.')[1]))
        identity = json.loads(oauth.unbase64(tokens['id_token'].split('.')[1]))
        observations[label] = {'service_expires_in': service['expires_in'], 'service_lifetime': claims['exp'] - claims['iat'], 'code_expires_in': tokens['expires_in'], 'access_lifetime': access['exp'] - access['iat'], 'id_lifetime': identity['exp'] - identity['iat']}

    def update(label, payload):
        status, _, body = send_raw(admin_base, 'PUT', json.dumps(payload).encode(), auth)
        observations[label] = {'status': status, 'body': json.loads(body) if body else None}

    def login_page(label):
        query = urllib.parse.urlencode({'client_id': 'user-app', 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 'state'})
        status, _, body = send(issuer + '/protocol/openid-connect/auth?' + query)
        text = body.decode()
        observations[label] = {'status': status, 'shows_display_name': 'Shown Realm' in text, 'shows_realm_name': realm in text}

    try:
        realm_fields('defaults')
        lifetimes('lifetimes/defaults')
        login_page('login-page/default')
        update('update/settings', {'displayName': 'Shown Realm', 'accessTokenLifespan': 60})
        realm_fields('after-update')
        lifetimes('lifetimes/after-update')
        login_page('login-page/display-name')
        update('update/zero-lifespan', {'accessTokenLifespan': 0})
        realm_fields('after-zero')
        update('update/negative-lifespan', {'accessTokenLifespan': -5})
        realm_fields('after-negative')
        update('update/text-lifespan', {'accessTokenLifespan': 'abc'})
        update('update/clear-display-name', {'displayName': ''})
        realm_fields('after-clear')
        baseline = pathlib.Path(__file__).with_name('realm-setting-observations.json')
        assert record or baseline.exists(), 'reference realm setting baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference realm setting case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference realm setting case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Realm displayName and accessTokenLifespan: defaults, updates and invalid values, token lifetimes for client-credentials and code flows, and the login page; selected fields and lifetimes only.', 'normalization': 'None needed: only setting values and lifetimes are kept.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference realm setting check failed: {detail}') from None
