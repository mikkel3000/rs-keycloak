#!/usr/bin/env python3
"""Capture the texts of pinned Keycloak's login pages in each locale.

Covers the login, OTP, CONFIGURE_TOTP, UPDATE_PASSWORD, UPDATE_PROFILE,
VERIFY_EMAIL, consent and forgot-password pages: their title, heading,
labels, buttons, links, messages and field errors from the login theme's
message bundles, the fallback from a locale through its parent locales, the
realm default and English, and the language choice, whose links re-show the
page in the chosen locale through a kc_locale login-actions URL.
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
from otp import Forms, totp

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
    prefix, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    callback = base + '/callback'
    i18n = {'internationalizationEnabled': True, 'supportedLocales': LOCALES, 'defaultLocale': 'fr'}
    settings = {
        'i18n': i18n | {'resetPasswordAllowed': True},
        'nodefault': {'internationalizationEnabled': True, 'supportedLocales': ['en', 'de', 'de-CH']},
        'off': {'internationalizationEnabled': False, 'supportedLocales': ['en', 'de'], 'defaultLocale': 'de', 'resetPasswordAllowed': True},
        'single': {'internationalizationEnabled': True, 'supportedLocales': ['de'], 'defaultLocale': 'de'},
        'verify': i18n | {'verifyEmail': True},
    }
    names = {key: f'{prefix}-{key}' for key in settings}
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
        status, _, body = call('/admin/realms' + path, {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}, method, data)
        return status, json.loads(body) if body else None

    class Browser:
        """One browser: a cookie jar, and the Set-Cookie headers of its last response."""

        def __init__(self, key):
            self.key, self.cookies, self.set_cookies = key, {}, []

        def send(self, path, headers=None, method='GET', body=None):
            """Sends a request and follows redirects that stay in login-actions."""
            self.set_cookies = []
            while True:
                sent = dict(headers or {})
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

        def authorize(self, locale=None, client='login-app'):
            verifier = secrets.token_urlsafe(48)
            extra = {'ui_locales': locale} if locale else {}
            query = urllib.parse.urlencode({'client_id': client, 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': b64(hashlib.sha256(verifier.encode()).digest()), 'code_challenge_method': 'S256'} | extra)
            return self.send(f'/realms/{names[self.key]}/protocol/openid-connect/auth?' + query)

        def submit(self, response, fields, form_id=None):
            """Posts the page's form (the first, or the one with the id) with the fields added."""
            forms = Forms()
            forms.feed(response[2].decode())
            form = next(form for form in forms.forms if form_id in (None, form['id']))
            action = urllib.parse.urlsplit(urllib.parse.urljoin(base, form['action']))
            target = action.path + ('?' + action.query if action.query else '')
            return self.send(target, {'Content-Type': 'application/x-www-form-urlencoded'}, 'POST', urllib.parse.urlencode(form['fields'] | fields))

        def follow(self, response, locale):
            """Follows the page's language link for a locale."""
            text = response[2].decode()
            link = re.search(r'<option\s+value="([^"]*kc_locale=' + re.escape(locale) + r'(?:&[^"]*)?)"', text)
            assert link, f'no language link for {locale}'
            href = urllib.parse.urlsplit(urllib.parse.urljoin(base, link.group(1).replace('&amp;', '&')))
            return self.send(href.path + '?' + href.query)

    def shown(response, browser):
        """The page's status, lang and dir, locale cookies and texts."""
        status, headers, body = response
        result = {'status': status, 'locale_cookie': [value for value in browser.set_cookies if value.startswith('KEYCLOAK_LOCALE=')]}
        if status != 200:
            result['location'] = urllib.parse.urlsplit(headers.get('location', '')).path.replace(base, '')
            return result
        tag = re.search(r'<html[^>]*>', body.decode()).group(0)
        lang, direction = re.search(r'\blang="([^"]*)"', tag), re.search(r'\bdir="([^"]*)"', tag)
        texts = page_texts(body)
        # The reference lists consent scopes in hash order.
        texts['items'].sort()
        return result | {'lang': lang and lang.group(1), 'dir': direction and direction.group(1)} | {key: value for key, value in texts.items() if value not in (None, [], {})}

    def new_user(key, case, extra=None):
        username = case + '-user'
        status, _ = admin_call(f'/{names[key]}/users', 'POST', {'username': username, 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': case + '@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]} | (extra or {}))
        assert status == 201, f'user creation {status} for {key}/{case}'
        return username

    def sign_in(key, case, locale, extra=None, client='login-app'):
        login = new_user(key, case, extra)
        browser = Browser(key)
        page = browser.authorize(locale, client)
        return browser, browser.submit(page, {'username': login, 'password': password, 'credentialId': ''})

    with SmtpSink() as sink:
        smtp = {'host': '127.0.0.1', 'port': str(sink.port), 'from': 'noreply@example.invalid'}
        clients = [
            {'clientId': 'login-app', 'publicClient': True, 'redirectUris': [callback]},
            {'clientId': 'consent-app', 'publicClient': True, 'consentRequired': True, 'redirectUris': [callback]},
        ]
        for key, extra in settings.items():
            oauth.request(base + '/admin/realms', {'realm': names[key], 'enabled': True, 'sslRequired': 'none', 'displayName': DISPLAY_NAME, 'smtpServer': smtp, 'clients': clients} | extra, admin, expected=201)
        try:
            # The login page in each locale, and a failed sign-in.
            for locale in LOCALES:
                browser = Browser('i18n')
                page = browser.authorize(locale)
                observations[f'login/i18n/{locale}'] = shown(page, browser)
                if locale in ('de', 'de-CH', 'lv', 'eo', 'ar'):
                    response = browser.submit(page, {'username': 'nobody', 'password': 'wrong', 'credentialId': ''})
                    observations[f'login-failed/i18n/{locale}'] = shown(response, browser)
            for key, locale in (('nodefault', 'de-CH'), ('nodefault', None), ('off', 'de'), ('single', None)):
                browser = Browser(key)
                page = browser.authorize(locale)
                observations[f'login/{key}/{locale or "none"}'] = shown(page, browser)
                if key == 'nodefault' and locale:
                    response = browser.submit(page, {'username': 'nobody', 'password': 'wrong', 'credentialId': ''})
                    observations[f'login-failed/{key}/{locale}'] = shown(response, browser)

            # Language links re-show the page and keep working.
            browser = Browser('i18n')
            page = browser.authorize('de')
            switched = browser.follow(page, 'ar')
            observations['switch/login/to-ar'] = shown(switched, browser)
            response = browser.submit(switched, {'username': 'nobody', 'password': 'wrong', 'credentialId': ''})
            observations['switch/login/failed-after'] = shown(response, browser)

            # Forgot password.
            for locale in ('de', 'ar', 'lv'):
                browser = Browser('i18n')
                page = browser.authorize(locale)
                forgot = re.search(r'href="([^"]*/login-actions/reset-credentials[^"]*)"', page[2].decode()).group(1).replace('&amp;', '&')
                reset = browser.send(urllib.parse.urlsplit(forgot).path + '?' + urllib.parse.urlsplit(forgot).query)
                observations[f'reset/i18n/{locale}'] = shown(reset, browser)
                if locale == 'de':
                    observations['reset-empty/i18n/de'] = shown(browser.submit(reset, {'username': ''}), browser)
                    switched = browser.follow(reset, 'fr')
                    observations['switch/reset/to-fr'] = shown(switched, browser)
                    login = new_user('i18n', 'reset-de')
                    observations['reset-sent/i18n/fr'] = shown(browser.submit(switched, {'username': login}), browser)
                    # The emailed link, opened in the same browser.
                    _, link = mail_summary(sink.wait(1)[-1], base, names['i18n'])
                    href = urllib.parse.urlsplit(link)
                    page = browser.send(href.path + '?' + href.query)
                    observations['reset-link/i18n/de'] = shown(page, browser)
                    response = browser.submit(page, {'password-new': 'one', 'password-confirm': 'two'})
                    observations['reset-link-mismatch/i18n/de'] = shown(response, browser)
                    observations['switch/reset-link/to-fr'] = shown(browser.follow(response, 'fr'), browser)
            browser = Browser('off')
            page = browser.authorize('de')
            forgot = re.search(r'href="([^"]*/login-actions/reset-credentials[^"]*)"', page[2].decode()).group(1).replace('&amp;', '&')
            observations['reset/off/de'] = shown(browser.send(urllib.parse.urlsplit(forgot).path + '?' + urllib.parse.urlsplit(forgot).query), browser)

            # Required actions.
            for locale in ('de', 'ar', 'eo'):
                browser, page = sign_in('i18n', f'password-{locale}', locale, {'requiredActions': ['UPDATE_PASSWORD']})
                observations[f'update-password/i18n/{locale}'] = shown(page, browser)
                if locale == 'de':
                    response = browser.submit(page, {'password-new': 'one', 'password-confirm': 'two'})
                    observations['update-password-mismatch/i18n/de'] = shown(response, browser)
                    response = browser.submit(response, {'password-new': '', 'password-confirm': ''})
                    observations['update-password-empty/i18n/de'] = shown(response, browser)
                    switched = browser.follow(response, 'pt-BR')
                    observations['switch/update-password/to-pt-BR'] = shown(switched, browser)
            for locale in ('de', 'zh-CN'):
                browser, page = sign_in('i18n', f'profile-{locale}', locale, {'requiredActions': ['UPDATE_PROFILE']})
                observations[f'update-profile/i18n/{locale}'] = shown(page, browser)
                response = browser.submit(page, {'firstName': '', 'lastName': '', 'email': ''})
                observations[f'update-profile-empty/i18n/{locale}'] = shown(response, browser)
                if locale == 'de':
                    response = browser.submit(response, {'firstName': 'Changed', 'lastName': 'User', 'email': 'not-an-email'})
                    observations['update-profile-invalid-email/i18n/de'] = shown(response, browser)
                    switched = browser.follow(response, 'ar')
                    observations['switch/update-profile/to-ar'] = shown(switched, browser)
            for locale in ('de', 'pt-BR'):
                browser, page = sign_in('i18n', f'totp-{locale}', locale, {'requiredActions': ['CONFIGURE_TOTP']})
                observations[f'configure-totp/i18n/{locale}'] = shown(page, browser)
                forms = Forms()
                forms.feed(page[2].decode())
                secret = forms.forms[0]['fields']['totpSecret']
                wrong = '000000' if totp(secret) != '000000' else '111111'
                response = browser.submit(page, {'totp': wrong, 'userLabel': ''})
                observations[f'configure-totp-wrong/i18n/{locale}'] = shown(response, browser)
                response = browser.submit(response, {'totp': '', 'userLabel': ''})
                observations[f'configure-totp-empty/i18n/{locale}'] = shown(response, browser)
                if locale == 'de':
                    switched = browser.follow(response, 'fr')
                    observations['switch/configure-totp/to-fr'] = shown(switched, browser)
                    response = browser.submit(switched, {'totp': totp(secret), 'userLabel': ''})
                    # A second sign-in asks for the code.
                    second = Browser('i18n')
                    page = second.authorize('de')
                    page = second.submit(page, {'username': 'totp-de-user', 'password': password, 'credentialId': ''})
                    observations['otp/i18n/de'] = shown(page, second)
                    response = second.submit(page, {'otp': wrong})
                    observations['otp-wrong/i18n/de'] = shown(response, second)
                    switched = second.follow(response, 'ar')
                    observations['switch/otp/to-ar'] = shown(switched, second)
            for locale in ('de', 'lv'):
                browser, page = sign_in('verify', f'verify-{locale}', locale, {'emailVerified': False})
                observations[f'verify-email/verify/{locale}'] = shown(page, browser)
                if locale == 'de':
                    switched = browser.follow(page, 'fr')
                    observations['switch/verify-email/to-fr'] = shown(switched, browser)

            # Consent.
            for locale in ('de', 'ar', 'de-CH'):
                browser, page = sign_in('i18n', f'consent-{locale}', locale, client='consent-app')
                observations[f'consent/i18n/{locale}'] = shown(page, browser)
                if locale == 'de':
                    switched = browser.follow(page, 'fr')
                    observations['switch/consent/to-fr'] = shown(switched, browser)
        finally:
            for name in names.values():
                oauth.request(base + '/admin/realms/' + name, token=admin, method='DELETE', expected=204)

    observations = json.loads(json.dumps(observations).replace(base, '{base}'))
    for key in sorted(names, key=lambda item: -len(names[item])):
        observations = json.loads(json.dumps(observations).replace(names[key], '{realm-' + key + '}'))
    baseline = pathlib.Path(__file__).with_name('login-message-observations.json')
    assert record or baseline.exists(), 'reference login messages baseline missing'
    if not record:
        expected = json.loads(baseline.read_text())['observations']
        assert observations.keys() == expected.keys(), 'reference login messages case inventory changed'
        for label in observations:
            assert observations[label] == expected[label], f'reference login messages case changed: {label}: {observations[label]}'
    lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
    return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Texts of the login, OTP, CONFIGURE_TOTP, UPDATE_PASSWORD, UPDATE_PROFILE, VERIFY_EMAIL, consent and forgot-password pages in each locale, with fallback through parent locales, the realm default and English, and the language links that re-show each page.', 'normalization': 'The base URL and realm names are replaced with placeholders; pages are reduced by tests/page_texts.py to title, heading, labels, buttons, login-actions links, list items, messages, field errors and the language choice (label, selected, login-actions step, kc_locale).', 'observations': observations}


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        raise SystemExit(f'reference login messages check failed: {error}') from None
