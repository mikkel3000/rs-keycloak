#!/usr/bin/env python3
"""Capture pinned Keycloak account REST API behavior via public HTTP only."""
import base64
import hashlib
import http.cookiejar
import json
import pathlib
import secrets
import urllib.parse
import urllib.request

import oauth
from admin_realms import send_raw
from tokens import send


def shape(response):
    status, headers, body = response
    parsed = json.loads(body) if body and (headers.get_content_type() or '').endswith('json') else None
    result = {'status': status, 'www_authenticate': bool(headers.get('WWW-Authenticate'))}
    if isinstance(parsed, dict):
        result['fields'] = sorted(parsed)
        result['body'] = {key: parsed[key] for key in ('username', 'firstName', 'lastName', 'email', 'emailVerified', 'error', 'errorMessage', 'field') if key in parsed}
    elif isinstance(parsed, list):
        result['length'] = len(parsed)
        result['item_fields'] = sorted({field for item in parsed for field in item}) if parsed and isinstance(parsed[0], dict) else []
    return result


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    callback = base + '/callback'
    user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
    other = {'username': 'other-user', 'enabled': True, 'firstName': 'Other', 'lastName': 'User', 'email': 'other@example.invalid', 'emailVerified': True}
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [{'clientId': 'plain-app', 'publicClient': True, 'redirectUris': [callback]}]}, admin, expected=201)
    # Users created through the admin API receive the realm's default roles,
    # which grant the account client roles; imported users do not.
    for entry in (user, other):
        oauth.request(base + '/admin/realms/' + realm + '/users', entry, admin, expected=201)
    observations = {}
    issuer = base + '/realms/' + realm
    try:
        account_redirect = issuer + '/account/'
        def user_token(client, redirect):
            policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https', 'wss'))
            browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), StopAt(redirect))
            verifier = secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
            query = urllib.parse.urlencode({'client_id': client, 'redirect_uri': redirect, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': challenge, 'code_challenge_method': 'S256'})
            form = oauth.Form()
            form.feed(send(issuer + '/protocol/openid-connect/auth?' + query, opener=browser)[2].decode())
            status, headers, _ = send(form.action, list((form.fields | {'username': 'reference-user', 'password': password, 'credentialId': ''}).items()), opener=browser)
            location = urllib.parse.urlsplit(headers['Location'])
            params = urllib.parse.parse_qs(location.query)
            if 'code' not in params:
                raise AssertionError(f'login for {client} redirected to {location.path} with {sorted(params)} {params.get("error")}')
            code = params['code'][0]
            _, _, body = send(issuer + '/protocol/openid-connect/token', [('grant_type', 'authorization_code'), ('client_id', client), ('redirect_uri', redirect), ('code', code), ('code_verifier', verifier)])
            return json.loads(body)['access_token']

        account = user_token('account-console', account_redirect)
        plain = user_token('plain-app', callback)
        claims = json.loads(oauth.unbase64(account.split('.')[1]))
        observations['token/account-console'] = {'aud': claims.get('aud'), 'resource_access': sorted(claims.get('resource_access', {}).get('account', {}).get('roles', []))}
        api = issuer + '/account'
        headers = lambda token: {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}
        observations['profile/no-token'] = shape(send_raw(api, 'GET', None, {'Accept': 'application/json'}))
        observations['profile/plain-client-token'] = shape(send_raw(api, 'GET', None, headers(plain)))
        observations['profile/read'] = shape(send_raw(api, 'GET', None, headers(account)))
        update = lambda body: send_raw(api, 'POST', json.dumps(body).encode(), dict(headers(account), **{'Content-Type': 'application/json'}))
        observations['profile/update'] = shape(update({'username': 'reference-user', 'firstName': 'Changed', 'lastName': 'Person', 'email': 'reference@example.invalid'}))
        observations['profile/after-update'] = shape(send_raw(api, 'GET', None, headers(account)))
        observations['profile/update-taken-email'] = shape(update({'username': 'reference-user', 'firstName': 'Changed', 'lastName': 'Person', 'email': 'other@example.invalid'}))
        observations['profile/update-missing-first-name'] = shape(update({'username': 'reference-user', 'firstName': '', 'lastName': 'Person', 'email': 'reference@example.invalid'}))
        observations['credentials/list'] = shape(send_raw(api + '/credentials', 'GET', None, headers(account)))
        observations['sessions/list'] = shape(send_raw(api + '/sessions', 'GET', None, headers(account)))
        baseline = pathlib.Path(__file__).with_name('account-api-observations.json')
        assert record or baseline.exists(), 'reference account API baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference account API case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference account API case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Account REST API profile read and update, credentials and sessions with an account-console token, another client token and no token; field names and selected values only.', 'normalization': 'Bodies are reduced to field names and selected profile values.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


class StopAt(urllib.request.HTTPRedirectHandler):
    def __init__(self, prefix):
        self.prefix = prefix

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.startswith(self.prefix):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference account API check failed: {detail}') from None
