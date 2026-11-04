#!/usr/bin/env python3
"""Capture pinned Keycloak TOTP setup and login behavior via public HTTP only."""
import hashlib
import hmac
import html.parser
import http.cookiejar
import json
import pathlib
import secrets
import struct
import time
import urllib.parse
import urllib.request

import oauth
from admin_realms import send_raw
from tokens import send


class Forms(html.parser.HTMLParser):
    """Collects each form's id, action and input names."""

    def __init__(self):
        super().__init__()
        self.forms = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.forms.append({'id': attrs.get('id'), 'action': attrs.get('action'), 'fields': {}})
        elif tag == 'input' and self.forms and attrs.get('name'):
            self.forms[-1]['fields'][attrs['name']] = attrs.get('value', '')


def totp(secret, at=None, digits=6, period=30):
    """RFC 6238 with Keycloak's defaults: the secret string's bytes, HMAC-SHA1."""
    counter = int((at or time.time()) // period)
    digest = hmac.new(secret.encode(), struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0f
    value = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff
    return str(value % 10 ** digits).zfill(digits)


def page(response):
    status, headers, body = response
    if status in (302, 303):
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(headers['Location']).query)
        return {'status': status, 'location_params': sorted(params)}, None
    forms = Forms()
    forms.feed(body.decode(errors='replace'))
    form = forms.forms[0] if forms.forms else {'id': None, 'action': None, 'fields': {}}
    return {'status': status, 'form': form['id'], 'fields': sorted(form['fields'])}, form


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(40)
    callback = base + '/callback'
    user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'requiredActions': ['CONFIGURE_TOTP'], 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [{'clientId': 'otp-app', 'publicClient': True, 'redirectUris': [callback]}], 'users': [user]}, admin, expected=201)
    observations = {}
    issuer = base + '/realms/' + realm
    auth = {'Authorization': 'Bearer ' + admin}
    users = base + '/admin/realms/' + realm + '/users'
    user_id = json.loads(send_raw(users + '?username=reference-user&exact=true', 'GET', None, auth)[2])[0]['id']

    def browser():
        policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https', 'wss'))
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), oauth.Redirects())

    def password_step(opener):
        query = urllib.parse.urlencode({'client_id': 'otp-app', 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'code_challenge_method': 'S256'})
        form = oauth.Form()
        form.feed(send(issuer + '/protocol/openid-connect/auth?' + query, opener=opener)[2].decode())
        return send(form.action, list((form.fields | {'username': 'reference-user', 'password': password, 'credentialId': ''}).items()), opener=opener)

    def submit(opener, form, fields):
        return send(urllib.parse.urljoin(issuer, form['action']), list((form['fields'] | fields).items()), opener=opener)

    try:
        setup_browser = browser()
        observations['setup/page'], form = page(password_step(setup_browser))
        secret = form['fields']['totpSecret']
        observations['setup/secret'] = {'length': len(secret), 'alphanumeric': secret.isalnum()}
        observations['setup/wrong-code'], form = page(submit(setup_browser, form, {'totp': '000000' if totp(secret) != '000000' else '111111', 'userLabel': 'phone'}))
        observations['setup/missing-code'], form = page(submit(setup_browser, form, {'totp': '', 'userLabel': 'phone'}))
        observations['setup/correct-code'], _ = page(submit(setup_browser, form, {'totp': totp(secret), 'userLabel': 'phone'}))
        credentials = json.loads(send_raw(users + '/' + user_id + '/credentials', 'GET', None, auth)[2])
        otp = next(credential for credential in credentials if credential['type'] == 'otp')
        observations['admin/credentials'] = {'types': sorted(credential['type'] for credential in credentials), 'otp_fields': sorted(otp), 'otp_label': otp.get('userLabel')}
        rep = json.loads(send_raw(users + '/' + user_id, 'GET', None, auth)[2])
        observations['admin/user-after-setup'] = {'totp': rep.get('totp'), 'requiredActions': rep.get('requiredActions')}
        # A new 30-second window keeps the setup code from counting as reuse.
        time.sleep(30 - time.time() % 30 + 1)
        login_browser = browser()
        observations['login/otp-page'], form = page(password_step(login_browser))
        observations['login/wrong-code'], form = page(submit(login_browser, form, {'otp': '000000' if totp(secret) != '000000' else '111111'}))
        code = totp(secret)
        observations['login/correct-code'], _ = page(submit(login_browser, form, {'otp': code}))
        reuse_browser = browser()
        _, form = page(password_step(reuse_browser))
        observations['login/reused-code'], _ = page(submit(reuse_browser, form, {'otp': code}))
        observations['admin/delete-otp'] = {'status': send_raw(users + '/' + user_id + '/credentials/' + otp['id'], 'DELETE', None, auth)[0]}
        observations['login/after-delete'], _ = page(password_step(browser()))
        baseline = pathlib.Path(__file__).with_name('otp-observations.json')
        assert record or baseline.exists(), 'reference OTP baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference OTP case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference OTP case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'CONFIGURE_TOTP setup, OTP login with wrong, correct and reused codes, admin credential listing and deletion; form ids, field names and redirect shapes only, never secrets or codes.', 'normalization': 'Pages are reduced to form id and field names; a rejected code shows the same form again.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference OTP check failed: {detail}') from None
