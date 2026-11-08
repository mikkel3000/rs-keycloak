#!/usr/bin/env python3
"""Capture pinned Keycloak's loginWithEmailAllowed and duplicateEmailsAllowed
effects.

Covers the login form's username label, signing in and asking for a
password reset with a username or an email (KeycloakModelUtils.
findUserByNameOrEmail and ResetCredentialChooseUser: the email is looked up
first only when email login is allowed and the input has an '@'), the
login error when several users share the email, and the uniqueness checks
of admin user creation and update and of UPDATE_PROFILE
(DuplicateEmailValidator, DuplicateUsernameValidator), with the realm
representation's two settings.
"""
import base64
import hashlib
import http.client
import json
import pathlib
import re
import secrets
import sys
import urllib.parse

import oauth
from otp import Forms

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from page_texts import page_texts  # noqa: E402
from smtp_sink import SmtpSink  # noqa: E402

SETTINGS = {
    'default': {},
    'noemail': {'loginWithEmailAllowed': False},
    'dupes': {'duplicateEmailsAllowed': True},
    'dupes-noemail': {'duplicateEmailsAllowed': True, 'loginWithEmailAllowed': False},
    'email-username': {'registrationEmailAsUsername': True},
    'email-username-noemail': {'registrationEmailAsUsername': True, 'loginWithEmailAllowed': False},
}


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def run(base, bootstrap_secret, record=False):
    location = urllib.parse.urlsplit(base)
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    prefix, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    names = {key: f'{prefix}-{key}' for key in SETTINGS}
    callback = base + '/callback'
    observations = {}

    def call(path, headers=None, method='GET', body=None):
        connection = http.client.HTTPConnection(location.hostname, location.port, timeout=15)
        try:
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read()
        finally:
            connection.close()

    def admin_call(key, path, method='GET', payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        status, _, body = call(f'/admin/realms/{names[key]}' + path, {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}, method, data)
        return status, json.loads(body) if body else None

    def admin_result(key, path, method='GET', payload=None):
        status, body = admin_call(key, path, method, payload)
        result = {'status': status}
        if isinstance(body, dict):
            result['body'] = {field: body[field] for field in ('errorMessage', 'field', 'params') if field in body}
        return result

    class Browser:
        """One browser: a cookie jar."""

        def __init__(self, key):
            self.key, self.cookies = key, {}

        def send(self, path, headers=None, method='GET', body=None):
            """Sends a request and follows redirects that stay in login-actions."""
            while True:
                sent = dict(headers or {})
                jar = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
                if jar:
                    sent['Cookie'] = jar
                status, pairs, data = call(path, sent, method, body)
                for header, value in pairs:
                    if header.lower() == 'set-cookie':
                        cookie, _, rest = value.partition('=')
                        content = rest.split(';', 1)[0]
                        if content and 'max-age=0' not in value.lower():
                            self.cookies[cookie] = content
                        else:
                            self.cookies.pop(cookie, None)
                found = dict((k.lower(), v) for k, v in pairs)
                target = urllib.parse.urlsplit(urllib.parse.urljoin(base, found.get('location', '')))
                if status not in (302, 303) or '/login-actions/' not in target.path:
                    return status, found, data
                path, method, body = target.path + ('?' + target.query if target.query else ''), 'GET', None
                headers = {}

        def authorize(self):
            verifier = secrets.token_urlsafe(48)
            query = urllib.parse.urlencode({'client_id': 'login-app', 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': b64(hashlib.sha256(verifier.encode()).digest()), 'code_challenge_method': 'S256'})
            return self.send(f'/realms/{names[self.key]}/protocol/openid-connect/auth?' + query)

        def submit(self, response, fields):
            forms = Forms()
            forms.feed(response[2].decode())
            form = forms.forms[0]
            action = urllib.parse.urlsplit(urllib.parse.urljoin(base, form['action'].replace('&amp;', '&')))
            target = action.path + ('?' + action.query if action.query else '')
            return self.send(target, {'Content-Type': 'application/x-www-form-urlencoded'}, 'POST', urllib.parse.urlencode(form['fields'] | fields))

    def shown(response):
        """A redirect's target, or the page's texts."""
        status, headers, data = response
        if status in (302, 303):
            target = urllib.parse.urlsplit(headers.get('location', ''))
            return {'status': status, 'location': target.path.replace(location.path, '') if target.netloc else target.path, 'code': 'code' in urllib.parse.parse_qs(target.query)}
        texts = page_texts(data)
        return {'status': status} | {key: value for key, value in texts.items() if key != 'languages' and value not in (None, [], {})}

    def new_user(key, username, email, extra=None):
        user = {'username': username, 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]} | ({'email': email} if email else {}) | (extra or {})
        status, body = admin_call(key, '/users', 'POST', user)
        assert status == 201, f'user creation {status} for {key}/{username}: {body}'
        _, found = admin_call(key, '/users?exact=true&username=' + urllib.parse.quote(username))
        return found[0]['id']

    def sign_in(key, login):
        browser = Browser(key)
        return shown(browser.submit(browser.authorize(), {'username': login, 'password': password, 'credentialId': ''}))

    with SmtpSink() as sink:
        smtp = {'host': '127.0.0.1', 'port': str(sink.port), 'from': 'noreply@example.invalid'}
        clients = [{'clientId': 'login-app', 'publicClient': True, 'redirectUris': [callback]}]
        for key, extra in SETTINGS.items():
            oauth.request(base + '/admin/realms', {'realm': names[key], 'enabled': True, 'sslRequired': 'none', 'resetPasswordAllowed': True, 'smtpServer': smtp, 'clients': clients} | extra, admin, expected=201)
        try:
            # The representation's settings.
            for key in ('default', 'dupes-noemail'):
                status, realm = admin_call(key, '')
                observations[f'representation/{key}'] = {'status': status, 'loginWithEmailAllowed': realm.get('loginWithEmailAllowed'), 'duplicateEmailsAllowed': realm.get('duplicateEmailsAllowed')}

            # The login form's username label.
            for key in SETTINGS:
                observations[f'login-form/{key}'] = shown(Browser(key).authorize())

            # Signing in with a username or an email.
            for key in ('default', 'noemail', 'dupes', 'dupes-noemail', 'email-username-noemail'):
                username = 'login-' + key if not key.startswith('email-username') else 'login@example.invalid'
                email = 'Login.Mail@example.invalid' if not key.startswith('email-username') else None
                new_user(key, username, email, {'email': username} if email is None else None)
                observations[f'sign-in/{key}/username'] = sign_in(key, username)
                if email:
                    observations[f'sign-in/{key}/email'] = sign_in(key, email)
                    observations[f'sign-in/{key}/email-lowercase'] = sign_in(key, email.lower())

            # A username with '@' that is another user's email.
            for key in ('default', 'noemail'):
                new_user(key, 'owner-' + key, 'shared-name@example.invalid')
                status, body = admin_call(key, '/users', 'POST', {'username': 'shared-name@example.invalid', 'enabled': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]})
                observations[f'create/username-is-other-email/{key}'] = {'status': status, 'body': {field: body[field] for field in ('errorMessage', 'field', 'params') if body and field in body}}
            observations['sign-in/noemail/username-with-at'] = sign_in('noemail', 'shared-name@example.invalid')

            # Several users with one email.
            for key in ('default', 'dupes', 'dupes-noemail'):
                new_user(key, 'first-' + key, 'twice@example.invalid')
                observations[f'create/duplicate-email/{key}'] = admin_result(key, '/users', 'POST', {'username': 'second-' + key, 'email': 'TWICE@example.invalid', 'enabled': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]})
                observations[f'create/email-is-other-username/{key}'] = admin_result(key, '/users', 'POST', {'username': 'third-' + key, 'email': 'first-' + key, 'enabled': True})
            observations['sign-in/dupes/shared-email'] = sign_in('dupes', 'twice@example.invalid')
            observations['sign-in/dupes/second-username'] = sign_in('dupes', 'second-dupes')
            observations['sign-in/dupes-noemail/shared-email'] = sign_in('dupes-noemail', 'twice@example.invalid')
            other = new_user('dupes', 'other-dupes', 'other@example.invalid')
            observations['update/to-shared-email/dupes'] = admin_result('dupes', f'/users/{other}', 'PUT', {'email': 'twice@example.invalid'})
            other = new_user('default', 'other-default', 'other@example.invalid')
            observations['update/to-shared-email/default'] = admin_result('default', f'/users/{other}', 'PUT', {'email': 'twice@example.invalid'})
            _, found = admin_call('dupes', '/users?email=twice@example.invalid&exact=true')
            observations['search/shared-email/dupes'] = sorted(user['username'] for user in found)

            # UPDATE_PROFILE to an email another user has.
            for key in ('default', 'dupes'):
                new_user(key, 'profile-' + key, 'profile-' + key + '@example.invalid', {'requiredActions': ['UPDATE_PROFILE']})
                browser = Browser(key)
                page = browser.submit(browser.authorize(), {'username': 'profile-' + key, 'password': password, 'credentialId': ''})
                observations[f'update-profile/to-shared-email/{key}'] = shown(browser.submit(page, {'firstName': 'Reference', 'lastName': 'User', 'email': 'twice@example.invalid'}))

            # Forgot password with a username or an email.
            for key, login in (('default', 'Login.Mail@example.invalid'), ('noemail', 'Login.Mail@example.invalid'), ('noemail', 'login-noemail'), ('dupes', 'twice@example.invalid'), ('dupes-noemail', 'twice@example.invalid')):
                browser = Browser(key)
                page = browser.authorize()
                forgot = re.search(r'href="([^"]*/login-actions/reset-credentials[^"]*)"', page[2].decode()).group(1).replace('&amp;', '&')
                parts = urllib.parse.urlsplit(forgot)
                form = browser.send(parts.path + '?' + parts.query)
                before = len(sink.received)
                result = shown(browser.submit(form, {'username': login}))
                # The reference sends the mail before it answers.
                mails = sink.wait(before + 1, timeout=1)[before:]
                observations[f'reset/{key}/{login}'] = result | {'mailed_to': sorted(address for mail in mails for address in mail['to'])}

            # Realm updates: each setting turns off the ones it excludes, in
            # the order the reference applies them.
            def settings(key):
                _, realm = admin_call(key, '')
                return {field: realm.get(field) for field in ('loginWithEmailAllowed', 'duplicateEmailsAllowed', 'registrationEmailAsUsername')}

            for label, key, changes in (
                ('duplicates-with-email-login', 'email-username', {'duplicateEmailsAllowed': True, 'loginWithEmailAllowed': True, 'registrationEmailAsUsername': True}),
                ('email-login-alone', 'email-username', {'loginWithEmailAllowed': True}),
                ('email-login-off', 'default', {'loginWithEmailAllowed': False}),
                ('email-login-on', 'dupes', {'loginWithEmailAllowed': True}),
            ):
                status, _ = admin_call(key, '', 'PUT', changes)
                observations[f'realm-update/{label}'] = {'status': status} | settings(key)
            # The shared email of users made while duplicates were allowed.
            observations['sign-in/dupes-later/shared-email'] = sign_in('dupes', 'twice@example.invalid')
            observations['sign-in/dupes-later/shared-email-username'] = sign_in('dupes', 'first-dupes')
            observations['create/dupes-later/shared-email'] = admin_result('dupes', '/users', 'POST', {'username': 'fourth-dupes', 'email': 'twice@example.invalid', 'enabled': True})
        finally:
            for name in names.values():
                oauth.request(base + '/admin/realms/' + name, token=admin, method='DELETE', expected=204)

    observations = json.loads(json.dumps(observations).replace(base, '{base}'))
    for key in sorted(names, key=lambda item: -len(names[item])):
        observations = json.loads(json.dumps(observations).replace(names[key], '{realm-' + key + '}'))
    baseline = pathlib.Path(__file__).with_name('login-email-observations.json')
    assert record or baseline.exists(), 'reference login email baseline missing'
    if not record:
        expected = json.loads(baseline.read_text())['observations']
        assert observations.keys() == expected.keys(), 'reference login email case inventory changed'
        for label in observations:
            assert observations[label] == expected[label], f'reference login email case changed: {label}: {observations[label]}'
    lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
    return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'loginWithEmailAllowed and duplicateEmailsAllowed: the login form label, sign-in and forgot-password by username or email, several users with one email, and the uniqueness checks of admin user creation and update and UPDATE_PROFILE.', 'normalization': 'The base URL and realm names are replaced with placeholders; pages are reduced by tests/page_texts.py without the language choice; redirects keep their path and whether they carry a code; admin errors keep errorMessage, field and params; mails keep their recipients.', 'observations': observations}


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        raise SystemExit(f'reference login email check failed: {error}') from None
