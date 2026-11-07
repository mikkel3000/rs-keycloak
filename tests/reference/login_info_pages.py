#!/usr/bin/env python3
"""Capture the texts of pinned Keycloak's info, error and logout pages in
each locale.

Covers the pages an execute-actions or verification email opens in a
browser without a login (the action list, the email confirmation, the
account-updated, email-verified and expired-link pages), the logout
confirmation and logged-out pages, the error pages of a refused
authorization or logout, and whether the TOTP setup page keeps its key when
it is re-shown. Each page's locale comes from what the reference reads
there: kc_locale picks through language links, ui_locales, the user's
locale, the KEYCLOAK_LOCALE cookie and Accept-Language.
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
from execute_actions import mail_summary
from otp import Forms

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from page_texts import page_texts  # noqa: E402
from smtp_sink import SmtpSink  # noqa: E402

LOCALES = ['en', 'de', 'de-CH', 'fr', 'pt-BR', 'zh-CN', 'ar', 'lv', 'eo']
DISPLAY_NAME = 'Localized Realm'


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def run(base, bootstrap_secret, record=False):
    location = urllib.parse.urlsplit(base)
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6) + '-info'
    password = secrets.token_urlsafe(30)
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

    def admin_call(path, method='GET', payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        status, _, body = call(f'/admin/realms/{realm}' + path, {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}, method, data)
        return status, json.loads(body) if body else None

    class Browser:
        """One browser: a cookie jar, a fixed Accept-Language, and the
        Set-Cookie headers of its last exchange."""

        def __init__(self, language=None):
            self.cookies, self.set_cookies = {}, []
            self.language = language
            self.verifier = None

        def send(self, path, headers=None, method='GET', body=None):
            """Sends a request and follows redirects that stay in login-actions."""
            self.set_cookies = []
            while True:
                sent = dict(headers or {})
                if self.language:
                    sent['Accept-Language'] = self.language
                jar = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
                if jar:
                    sent['Cookie'] = jar
                status, pairs, data = call(path, sent, method, body)
                hop = [value for header, value in pairs if header.lower() == 'set-cookie']
                self.set_cookies += hop
                for value in hop:
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
                headers = {key: value for key, value in (headers or {}).items() if key != 'Content-Type'}

        def visit(self, href):
            parts = urllib.parse.urlsplit(urllib.parse.urljoin(base, href.replace('&amp;', '&')))
            return self.send(parts.path + ('?' + parts.query if parts.query else ''))

        def authorize(self, query=None, client='login-app'):
            self.verifier = secrets.token_urlsafe(48)
            params = {'client_id': client, 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': b64(hashlib.sha256(self.verifier.encode()).digest()), 'code_challenge_method': 'S256'}
            return self.send(f'/realms/{realm}/protocol/openid-connect/auth?' + urllib.parse.urlencode(params | (query or {})))

        def logout(self, query=None):
            suffix = '?' + urllib.parse.urlencode(query) if query else ''
            return self.send(f'/realms/{realm}/protocol/openid-connect/logout' + suffix)

        def submit(self, response, fields):
            """Posts the page's first form with the fields added."""
            forms = Forms()
            forms.feed(response[2].decode())
            form = forms.forms[0]
            action = urllib.parse.urlsplit(urllib.parse.urljoin(base, form['action'].replace('&amp;', '&')))
            target = action.path + ('?' + action.query if action.query else '')
            return self.send(target, {'Content-Type': 'application/x-www-form-urlencoded'}, 'POST', urllib.parse.urlencode(form['fields'] | fields))

        def follow(self, response, locale):
            """Follows the page's language link for a locale."""
            text = response[2].decode()
            link = re.search(r'<option\s+value="([^"]*kc_locale=' + re.escape(locale) + r'(?:&[^"]*)?)"', text)
            assert link, f'no language link for {locale}'
            return self.visit(link.group(1))

        def proceed(self, response):
            """Follows the info page's link onwards."""
            link = re.search(r'<div id="kc-info-message">.*?<a href="([^"]*)"', response[2].decode(), re.S)
            assert link, 'no proceed link'
            return self.visit(link.group(1))

        def sign_in(self, login, query=None):
            """Signs in and returns the tokens of the code."""
            page = self.authorize(query)
            status, headers, _ = self.submit(page, {'username': login, 'password': password, 'credentialId': ''})
            assert status == 302, f'sign-in {status}'
            code = urllib.parse.parse_qs(urllib.parse.urlsplit(headers['location']).query)['code'][0]
            form = urllib.parse.urlencode({'grant_type': 'authorization_code', 'client_id': 'login-app', 'code': code, 'redirect_uri': callback, 'code_verifier': self.verifier})
            status, _, body = call(f'/realms/{realm}/protocol/openid-connect/token', {'Content-Type': 'application/x-www-form-urlencoded'}, 'POST', form)
            assert status == 200, f'token {status}'
            return json.loads(body)

    def shown(response, browser):
        """The page's status, lang and dir, locale cookies and texts."""
        status, headers, body = response
        result = {'status': status, 'locale_cookie': sorted(set(value for value in browser.set_cookies if value.startswith('KEYCLOAK_LOCALE=')))}
        if status in (302, 303):
            result['location'] = urllib.parse.urlsplit(headers.get('location', '')).path.replace(base, '')
            return result
        tag = re.search(r'<html[^>]*>', body.decode()).group(0)
        lang, direction = re.search(r'\blang="([^"]*)"', tag), re.search(r'\bdir="([^"]*)"', tag)
        texts = page_texts(body)
        return result | {'lang': lang and lang.group(1), 'dir': direction and direction.group(1)} | {key: value for key, value in texts.items() if value not in (None, [], {})}

    def new_user(case, extra=None):
        username = case + '-user'
        user = {'username': username, 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': case + '@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]} | (extra or {})
        status, _ = admin_call('/users', 'POST', user)
        assert status == 201, f'user creation {status} for {case}'
        _, found = admin_call('/users?exact=true&username=' + username)
        return username, found[0]['id']

    def emailed(path, payload=None):
        """Sends an admin email and returns its action link."""
        status, _ = admin_call(path, 'PUT', payload)
        assert status == 204, f'{path} {status}'
        _, link = mail_summary(sink.wait(1)[-1], base, realm)
        return link

    with SmtpSink() as sink:
        smtp = {'host': '127.0.0.1', 'port': str(sink.port), 'from': 'noreply@example.invalid'}
        clients = [
            {'clientId': 'login-app', 'publicClient': True, 'redirectUris': [callback], 'attributes': {'post.logout.redirect.uris': callback + '/logged-out'}},
            {'clientId': 'bearer-app', 'bearerOnly': True},
        ]
        oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'displayName': DISPLAY_NAME, 'smtpServer': smtp, 'clients': clients, 'internationalizationEnabled': True, 'supportedLocales': LOCALES, 'defaultLocale': 'fr'}, admin, expected=201)
        try:
            # The action list an execute-actions email opens, in the realm's
            # default, Accept-Language and the user's locale.
            _, plain = new_user('actions')
            link = emailed(f'/users/{plain}/execute-actions-email', ['UPDATE_PASSWORD'])
            browser = Browser()
            listed = browser.visit(link)
            observations['actions/default'] = shown(listed, browser)
            german = Browser('de')
            observations['actions/accept-de'] = shown(german.visit(link), german)
            _, arabic = new_user('actions-ar', {'attributes': {'locale': ['ar']}})
            other = Browser('de')
            observations['actions/user-ar'] = shown(other.visit(emailed(f'/users/{arabic}/execute-actions-email', ['UPDATE_PASSWORD'])), other)
            switched = browser.follow(listed, 'de')
            observations['switch/actions/to-de'] = shown(switched, browser)
            form = browser.proceed(switched)
            observations['actions-proceed/de'] = shown(form, browser)
            observations['actions-updated/de'] = shown(browser.submit(form, {'password-new': password + 'x', 'password-confirm': password + 'x'}), browser)
            observations['actions-reused/de'] = shown(browser.visit(link), browser)
            fresh = Browser('ar')
            observations['actions-reused/accept-ar'] = shown(fresh.visit(link), fresh)
            fresh = Browser('de')
            bogus = f'/realms/{realm}/login-actions/action-token?key=' + 'x' * 64
            observations['actions-invalid/accept-de'] = shown(fresh.send(bogus), fresh)

            # The email confirmation an admin-sent verification link opens.
            _, unverified = new_user('verify', {'emailVerified': False})
            link = emailed(f'/users/{unverified}/send-verify-email')
            browser = Browser('de')
            confirm = browser.visit(link)
            observations['verify-confirm/accept-de'] = shown(confirm, browser)
            switched = browser.follow(confirm, 'ar')
            observations['switch/verify-confirm/to-ar'] = shown(switched, browser)
            observations['verify-done/ar'] = shown(browser.proceed(switched), browser)
            observations['verify-reused/ar'] = shown(browser.visit(link), browser)
            fresh = Browser('de')
            observations['verify-reused/accept-de'] = shown(fresh.visit(link), fresh)

            # Logout without a session.
            browser = Browser('de')
            confirm = browser.logout()
            observations['logout-confirm/accept-de'] = shown(confirm, browser)
            other = Browser('de')
            observations['logout-confirm/ui-ar'] = shown(other.logout({'ui_locales': 'ar'}), other)
            switched = browser.follow(confirm, 'fr')
            observations['switch/logout-confirm/to-fr'] = shown(switched, browser)
            done = browser.submit(switched, {})
            observations['logged-out/fr'] = shown(done, browser)
            observations['switch/logged-out/to-de'] = shown(browser.follow(done, 'de'), browser)

            # Logout of a session, confirmed and by ID token hint.
            login, _ = new_user('logout-de', {'attributes': {'locale': ['de']}})
            browser = Browser('ar')
            browser.sign_in(login)
            confirm = browser.logout()
            observations['logout-confirm/session-de'] = shown(confirm, browser)
            observations['logged-out/session-de'] = shown(browser.submit(confirm, {}), browser)
            page = browser.authorize()
            observations['after-logout/login'] = {'status': page[0], 'form': bool(re.search(r'name="password"', page[2].decode()))}
            login, _ = new_user('logout-hint', {'attributes': {'locale': ['ar']}})
            browser = Browser('de')
            tokens = browser.sign_in(login)
            observations['logged-out/hint-ar'] = shown(browser.logout({'id_token_hint': tokens['id_token']}), browser)

            # Refused logouts and authorizations.
            for label, query in (
                ('logout-error/invalid-hint/accept-de', {'id_token_hint': 'not-a-token'}),
                ('logout-error/redirect/accept-de', {'client_id': 'login-app', 'post_logout_redirect_uri': 'https://elsewhere.invalid/'}),
                ('logout-error/redirect/ui-ar', {'client_id': 'login-app', 'post_logout_redirect_uri': 'https://elsewhere.invalid/', 'ui_locales': 'ar'}),
            ):
                browser = Browser('de')
                observations[label] = shown(browser.logout(query), browser)
            for label, query, client in (
                ('authorize-error/unknown-client/accept-de', None, 'missing-app'),
                ('authorize-error/redirect/accept-de', {'redirect_uri': 'https://elsewhere.invalid/'}, 'login-app'),
                ('authorize-error/redirect/ui-ar', {'redirect_uri': 'https://elsewhere.invalid/', 'ui_locales': 'ar'}, 'login-app'),
                ('authorize-error/bearer-only/accept-de', None, 'bearer-app'),
            ):
                browser = Browser('de')
                observations[label] = shown(browser.authorize(query, client), browser)
            browser = Browser('de')
            browser.cookies['KEYCLOAK_LOCALE'] = 'ar'
            observations['authorize-error/redirect/cookie-ar'] = shown(browser.authorize({'redirect_uri': 'https://elsewhere.invalid/'}), browser)

            # The TOTP setup page keeps its key when it is re-shown.
            login, _ = new_user('totp', {'requiredActions': ['CONFIGURE_TOTP']})
            browser = Browser()
            page = browser.submit(browser.authorize({'ui_locales': 'de'}), {'username': login, 'password': password, 'credentialId': ''})

            def key(response):
                forms = Forms()
                forms.feed(response[2].decode())
                return forms.forms[0]['fields']['totpSecret']

            first = key(page)
            switched = browser.follow(page, 'fr')
            wrong = browser.submit(switched, {'totp': '', 'userLabel': ''})
            # A new authorization opens a new authentication session, which
            # asks for the password again before it shows TOTP setup.
            again = browser.submit(browser.authorize({'ui_locales': 'de'}), {'username': login, 'password': password, 'credentialId': ''})
            observations['configure-totp/key'] = {'after_switch': key(switched) == first, 'after_error': key(wrong) == first, 'after_new_authorization': key(again) == first}
        finally:
            oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)

    observations = json.loads(json.dumps(observations).replace(base, '{base}').replace(realm, '{realm}'))
    baseline = pathlib.Path(__file__).with_name('login-info-page-observations.json')
    assert record or baseline.exists(), 'reference login info pages baseline missing'
    if not record:
        expected = json.loads(baseline.read_text())['observations']
        assert observations.keys() == expected.keys(), 'reference login info pages case inventory changed'
        for label in observations:
            assert observations[label] == expected[label], f'reference login info pages case changed: {label}: {observations[label]}'
    lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
    return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Texts of the action list, email confirmation, account-updated, email-verified and expired-link pages emailed links open, the logout confirmation and logged-out pages, and the error pages of refused authorizations and logouts, in the locale each page reads, with their language links; and whether the TOTP setup page keeps its key when re-shown.', 'normalization': 'The base URL and realm name are replaced with placeholders; pages are reduced by tests/page_texts.py to title, heading, labels, buttons, links, list items, messages, instructions, field errors and the language choice (label, selected, step, kc_locale); locale cookies of an exchange are a sorted set.', 'observations': observations}


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        raise SystemExit(f'reference login info pages check failed: {error}') from None
