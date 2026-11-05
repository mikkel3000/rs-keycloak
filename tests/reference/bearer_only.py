#!/usr/bin/env python3
"""Capture pinned Keycloak bearer-only clients and the bearer-only built-ins."""
import json
import pathlib
import secrets
import urllib.parse
import urllib.request

import oauth
from admin_clients import client_summary
from admin_realms import send_raw
from tokens import login, send, summary

URL_FIELDS = ['rootUrl', 'baseUrl', 'adminUrl', 'redirectUris', 'webOrigins', 'fullScopeAllowed', 'frontchannelLogout', 'consentRequired']


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    secret = secrets.token_urlsafe(40)
    callback = base + '/callback'
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [{'clientId': 'user-app', 'publicClient': True, 'redirectUris': [callback]}]}, admin, expected=201)
    oauth.request(base + '/admin/realms/' + realm + '/users', {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}, admin, expected=201)
    observations = {}
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    admin_base = base + '/admin/realms/' + realm
    issuer = base + '/realms/' + realm

    def clean(value):
        if isinstance(value, str):
            return value.replace(base, '{base}').replace(realm, '{realm}')
        if isinstance(value, list):
            return sorted(clean(item) for item in value)
        return value

    def call(label, method, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        response = send_raw(admin_base + path, method, data, auth)
        observation = client_summary(response, base, realm)
        if 'body' in observation:
            observation['body'] = {key: clean(value) for key, value in observation['body'].items()}
        observations[label] = observation
        return response

    def describe(label, client_id):
        client = json.loads(send_raw(admin_base + '/clients/' + client_id, 'GET', None, auth)[2])
        observations[label]['urls'] = {key: clean(client[key]) for key in URL_FIELDS if key in client}

    try:
        clients = json.loads(send_raw(admin_base + '/clients', 'GET', None, auth)[2])
        ids = {client['clientId']: client['id'] for client in clients}
        for name in ['broker', 'realm-management', 'security-admin-console', 'account', 'account-console', 'admin-cli']:
            call('builtin/' + name, 'GET', '/clients/' + ids[name])
            describe('builtin/' + name, ids[name])
            roles = json.loads(send_raw(admin_base + f'/clients/{ids[name]}/roles', 'GET', None, auth)[2])
            observations['builtin/' + name]['roles'] = sorted(role['name'] for role in roles)
        composite = json.loads(send_raw(admin_base + f"/clients/{ids['realm-management']}/roles/realm-admin/composites", 'GET', None, auth)[2])
        observations['realm-admin/composites'] = sorted(role['name'] for role in composite)
        for role in ['view-users', 'view-clients', 'manage-account']:
            owner = 'account' if role == 'manage-account' else 'realm-management'
            listed = json.loads(send_raw(admin_base + f'/clients/{ids[owner]}/roles/{role}/composites', 'GET', None, auth)[2])
            observations[f'composites/{role}'] = sorted(item['name'] for item in listed)
        created = call('create/bearer-only', 'POST', '/clients', {'clientId': 'api', 'bearerOnly': True, 'secret': secret})
        api = created[1]['Location'].rsplit('/', 1)[1]
        call('get/bearer-only', 'GET', '/clients/' + api)
        describe('get/bearer-only', api)
        call('secret/bearer-only', 'GET', f'/clients/{api}/client-secret')
        for name, extra in [('public', {'publicClient': True}), ('service-account', {'serviceAccountsEnabled': True})]:
            created = call('create/bearer-only-' + name, 'POST', '/clients', {'clientId': 'api-' + name, 'bearerOnly': True} | extra)
            call('get/bearer-only-' + name, 'GET', '/clients/' + created[1]['Location'].rsplit('/', 1)[1])
        browser = urllib.request.build_opener(oauth.Redirects())
        query = urllib.parse.urlencode({'client_id': 'api', 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 'state'})
        status, headers, body = send(issuer + '/protocol/openid-connect/auth?' + query, opener=browser)
        location = headers.get('Location')
        observations['authorize/bearer-only'] = {'status': status, 'content_type': headers.get('Content-Type'), 'location_query': sorted(urllib.parse.parse_qs(urllib.parse.urlparse(location).query)) if location else None, 'mentions_bearer_only': b'earer' in body}
        observations['token/client-credentials'] = summary(send(issuer + '/protocol/openid-connect/token', [('grant_type', 'client_credentials'), ('client_id', 'api'), ('client_secret', secret)]))
        observations['token/password'] = summary(send(issuer + '/protocol/openid-connect/token', [('grant_type', 'password'), ('client_id', 'api'), ('client_secret', secret), ('username', 'reference-user'), ('password', password)]))
        tokens, _ = login(issuer, 'user-app', None, password)
        introspect = issuer + '/protocol/openid-connect/token/introspect'
        observations['introspect/user-token'] = summary(send(introspect, [('token', tokens['access_token'])], basic=('api', secret)))
        observations['introspect/wrong-secret'] = summary(send(introspect, [('token', tokens['access_token'])], basic=('api', 'wrong')))
        observations['revoke/bearer-only'] = summary(send(issuer + '/protocol/openid-connect/revoke', [('token', tokens['refresh_token'])], basic=('api', secret)))
        baseline = pathlib.Path(__file__).with_name('bearer-only-observations.json')
        assert record or baseline.exists(), 'reference bearer-only baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference bearer-only case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference bearer-only case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Bearer-only client creation, reading, secrets, authorization, token, introspection and revocation, plus the six built-in clients with their URLs, roles and selected composites; names and selected fields only.', 'normalization': 'The random realm name and base URL are replaced with placeholders; secrets are reduced to presence.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f"reference bearer-only check failed: {detail}") from None
