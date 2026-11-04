#!/usr/bin/env python3
"""Capture pinned Keycloak UPDATE_PROFILE behavior via public HTTP only."""
import http.cookiejar
import json
import pathlib
import re
import secrets
import urllib.parse
import urllib.request

import oauth
from admin_realms import send_raw
from otp import page
from tokens import send


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    callback = base + '/callback'
    password = secrets.token_urlsafe(30)
    user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'requiredActions': ['UPDATE_PROFILE'], 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
    other = {'username': 'other-user', 'enabled': True, 'firstName': 'Other', 'lastName': 'User', 'email': 'other@example.invalid', 'emailVerified': True}
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [{'clientId': 'profile-app', 'publicClient': True, 'redirectUris': [callback]}], 'users': [user, other]}, admin, expected=201)
    observations = {}
    auth = {'Authorization': 'Bearer ' + admin}
    try:
        users = base + '/admin/realms/' + realm + '/users'
        user_id = json.loads(send_raw(users + '?username=reference-user&exact=true', 'GET', None, auth)[2])[0]['id']
        policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https', 'wss'))
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), oauth.Redirects())
        query = urllib.parse.urlencode({'client_id': 'profile-app', 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'code_challenge_method': 'S256'})
        form = oauth.Form()
        form.feed(send(base + '/realms/' + realm + '/protocol/openid-connect/auth?' + query, opener=browser)[2].decode())
        response = send(form.action, list((form.fields | {'username': 'reference-user', 'password': password, 'credentialId': ''}).items()), opener=browser)
        observations['login/profile-page'], form = page(response)
        observations['login/profile-page']['prefilled'] = sorted(name for name, value in form['fields'].items() if value)

        def submit(label, fields):
            nonlocal form
            response = send(urllib.parse.urljoin(base, form['action']), list((form['fields'] | fields).items()), opener=browser)
            observations[label], next_form = page(response)
            observations[label]['errors'] = sorted({name for name in re.findall(r'id="input-error-([a-zA-Z-]+)"', response[2].decode()) if not name.startswith('container-')})
            form = next_form or form

        submit('update/missing-first-name', {'firstName': '', 'lastName': 'Changed', 'email': 'changed@example.invalid'})
        submit('update/invalid-email', {'firstName': 'Changed', 'lastName': 'Changed', 'email': 'not-an-email'})
        submit('update/taken-email', {'firstName': 'Changed', 'lastName': 'Changed', 'email': 'other@example.invalid'})
        submit('update/success', {'firstName': 'Changed', 'lastName': 'Person', 'email': 'Changed@Example.invalid'})
        rep = json.loads(send_raw(users + '/' + user_id, 'GET', None, auth)[2])
        observations['admin/user-after'] = {key: rep.get(key) for key in ('username', 'firstName', 'lastName', 'email', 'emailVerified', 'requiredActions')}
        baseline = pathlib.Path(__file__).with_name('update-profile-observations.json')
        assert record or baseline.exists(), 'reference update profile baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference update profile case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference update profile case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'UPDATE_PROFILE at login: form fields and prefill, validation errors for missing first name, invalid and taken email, success, and the stored user afterwards.', 'normalization': 'Pages are reduced to form id, field names, prefilled field names and error field ids.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference update profile check failed: {detail}') from None
