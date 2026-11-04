#!/usr/bin/env python3
"""Capture pinned Keycloak temporary password and UPDATE_PASSWORD behavior."""
import http.cookiejar
import json
import pathlib
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
    user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True}
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [{'clientId': 'pw-app', 'publicClient': True, 'redirectUris': [callback]}], 'users': [user]}, admin, expected=201)
    observations = {}
    issuer = base + '/realms/' + realm
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    users = base + '/admin/realms/' + realm + '/users'
    user_id = json.loads(send_raw(users + '?username=reference-user&exact=true', 'GET', None, auth)[2])[0]['id']
    temporary, chosen = secrets.token_urlsafe(30), secrets.token_urlsafe(30)

    def browser():
        policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https', 'wss'))
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), oauth.Redirects())

    def password_step(opener, password):
        query = urllib.parse.urlencode({'client_id': 'pw-app', 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'code_challenge_method': 'S256'})
        form = oauth.Form()
        form.feed(send(issuer + '/protocol/openid-connect/auth?' + query, opener=opener)[2].decode())
        return send(form.action, list((form.fields | {'username': 'reference-user', 'password': password, 'credentialId': ''}).items()), opener=opener)

    def submit(opener, form, fields):
        return send(urllib.parse.urljoin(issuer, form['action']), list((form['fields'] | fields).items()), opener=opener)

    try:
        observations['admin/reset-temporary'] = {'status': send_raw(users + '/' + user_id + '/reset-password', 'PUT', json.dumps({'type': 'password', 'value': temporary, 'temporary': True}).encode(), auth)[0]}
        rep = json.loads(send_raw(users + '/' + user_id, 'GET', None, auth)[2])
        observations['admin/user-after-temporary'] = {'requiredActions': rep['requiredActions']}
        opener = browser()
        observations['login/update-page'], form = page(password_step(opener, temporary))
        observations['update/mismatch'], form = page(submit(opener, form, {'password-new': chosen, 'password-confirm': chosen + 'x'}))
        observations['update/empty'], form = page(submit(opener, form, {'password-new': '', 'password-confirm': ''}))
        observations['update/success'], _ = page(submit(opener, form, {'password-new': chosen, 'password-confirm': chosen}))
        rep = json.loads(send_raw(users + '/' + user_id, 'GET', None, auth)[2])
        observations['admin/user-after-update'] = {'requiredActions': rep['requiredActions']}
        observations['login/old-password'], _ = page(password_step(browser(), temporary))
        observations['login/new-password'], _ = page(password_step(browser(), chosen))
        baseline = pathlib.Path(__file__).with_name('update-password-observations.json')
        assert record or baseline.exists(), 'reference update password baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference update password case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference update password case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Temporary password reset, the UPDATE_PASSWORD form with mismatched and empty passwords, success, and login with old and new passwords; form ids, field names and redirect shapes only.', 'normalization': 'Pages are reduced to form id and field names; passwords are never retained.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference update password check failed: {detail}') from None
