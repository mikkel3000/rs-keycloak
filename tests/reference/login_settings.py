#!/usr/bin/env python3
"""Capture how pinned Keycloak's realm settings reach the login flow.

Covers realm internationalization on the login and required-action pages
(the locale chosen from kc_locale, the user's locale, ui_locales, the
KEYCLOAK_LOCALE cookie and Accept-Language, shown as html lang and dir), the
KEYCLOAK_LOCALE cookie and user locale that login sets, and how the
UPDATE_PROFILE required action and admin user updates follow
editUsernameAllowed and registrationEmailAsUsername.
"""
import base64
import hashlib
import http.client
import json
import pathlib
import re
import secrets
import urllib.parse

import oauth
from otp import Forms

MANY_LOCALES = ['en', 'de', 'fr', 'ar', 'pt-BR', 'zh-CN', 'ja', 'fa', 'he']


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def disabled_names(body):
    """Names of the page's disabled inputs."""
    return {name for tag in re.findall(r'<input\b[^>]*>', body.decode()) if re.search(r'\sdisabled\b', tag) for name in re.findall(r'\bname="([^"]+)"', tag)}


def run(base, bootstrap_secret, record=False):
    location = urllib.parse.urlsplit(base)
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    prefix, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    settings = {
        'i18n': {'internationalizationEnabled': True, 'supportedLocales': MANY_LOCALES, 'defaultLocale': 'de'},
        'pair': {'internationalizationEnabled': True, 'supportedLocales': ['en', 'de']},
        'off': {'internationalizationEnabled': False, 'supportedLocales': ['en', 'de'], 'defaultLocale': 'de'},
        'plain': {},
        'edit': {'editUsernameAllowed': True},
        'email': {'registrationEmailAsUsername': True},
        'both': {'editUsernameAllowed': True, 'registrationEmailAsUsername': True},
    }
    names = {key: f'{prefix}-{key}' for key in settings}
    for key, extra in settings.items():
        oauth.request(base + '/admin/realms', {'realm': names[key], 'enabled': True, 'sslRequired': 'none'} | extra, admin, expected=201)
    observations = {}

    def clean(value):
        for key in sorted(names, key=lambda item: -len(names[item])):
            value = value.replace(names[key], '{realm-' + key + '}')
        return value.replace(base, '{base}')

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

        def __init__(self, key, cookies=None):
            self.key, self.cookies, self.set_cookies, self.verifier = key, dict(cookies or {}), [], None

        def send(self, path, headers=None, method='GET', body=None):
            """Sends a request and follows redirects that stay in login-actions;
            set_cookies collects the Set-Cookie headers of every hop."""
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

        def authorize(self, client='account-console', headers=None, extra=None):
            self.verifier = secrets.token_urlsafe(48)
            self.client = client
            self.redirect = base + f'/realms/{names[self.key]}/account/'
            query = urllib.parse.urlencode({'client_id': client, 'redirect_uri': self.redirect, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': b64(hashlib.sha256(self.verifier.encode()).digest()), 'code_challenge_method': 'S256'} | (extra or {}))
            return self.send(f'/realms/{names[self.key]}/protocol/openid-connect/auth?' + query, headers)

        def submit(self, response, fields, headers=None, query=None):
            """Posts the page's first form with the given fields added."""
            forms = Forms()
            forms.feed(response[2].decode())
            form = forms.forms[0]
            action = urllib.parse.urlsplit(urllib.parse.urljoin(base, form['action']))
            target = action.path + ('?' + action.query if action.query else '')
            if query:
                target += ('&' if action.query else '?') + urllib.parse.urlencode(query)
            # A browser leaves disabled inputs out of the post.
            enabled = {name: value for name, value in form['fields'].items() if name not in disabled_names(response[2])}
            body = urllib.parse.urlencode(enabled | fields)
            return self.send(target, {'Content-Type': 'application/x-www-form-urlencoded'} | (headers or {}), 'POST', body)

        def token(self, response):
            code = urllib.parse.parse_qs(urllib.parse.urlsplit(response[1]['location']).query)['code'][0]
            status, _, body = call(f'/realms/{names[self.key]}/protocol/openid-connect/token', {'Content-Type': 'application/x-www-form-urlencoded'}, 'POST', urllib.parse.urlencode({'grant_type': 'authorization_code', 'client_id': self.client, 'redirect_uri': self.redirect, 'code': code, 'code_verifier': self.verifier}))
            return json.loads(body)['access_token']

    def locale_cookies(browser):
        return [value for value in browser.set_cookies if value.startswith('KEYCLOAK_LOCALE=')]

    def shown(response, browser):
        """The page's status, html lang and dir, and the locale cookies it set."""
        status, headers, body = response
        result = {'status': status, 'locale_cookie': locale_cookies(browser)}
        if status == 200:
            tag = re.search(r'<html[^>]*>', body.decode()).group(0)
            lang, direction = re.search(r'\blang="([^"]*)"', tag), re.search(r'\bdir="([^"]*)"', tag)
            result |= {'lang': lang and lang.group(1), 'dir': direction and direction.group(1)}
        else:
            result['location'] = urllib.parse.urlsplit(headers.get('location', '')).path
        return result

    def new_user(key, case, extra=None):
        username, email = case + '-user', case + '@example.invalid'
        status, _ = admin_call(f'/{names[key]}/users', 'POST', {'username': username, 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': email, 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]} | (extra or {}))
        assert status == 201, f'user creation {status} for {key}/{case}'
        _, found = admin_call(f'/{names[key]}/users?exact=true&username=' + urllib.parse.quote(email if key in ('email', 'both') else username))
        return found[0]['id'], (email if key in ('email', 'both') else username)

    def sign_in(key, login, headers=None, extra=None, query=None, cookies=None):
        browser = Browser(key, cookies)
        page = browser.authorize(headers=headers, extra=extra)
        return browser, browser.submit(page, {'username': login, 'password': password, 'credentialId': ''}, headers, query)

    def account(key, token, method='GET', payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        status, _, body = call(f'/realms/{names[key]}/account/', {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, method, data)
        return status, json.loads(body) if body else None

    def stored_locale(key, login):
        browser, response = sign_in(key, login)
        _, profile = account(key, browser.token(response))
        return profile.get('attributes', {}).get('locale')

    def user_with_locale(key, case, locale, extra=None):
        user_id, login = new_user(key, case)
        browser, response = sign_in(key, login)
        token = browser.token(response)
        _, own = account(key, token)
        status, _ = account(key, token, 'POST', {field: own[field] for field in ('username', 'email', 'firstName', 'lastName')} | {'attributes': {'locale': [locale]}})
        assert status == 204, f'locale setup {status}'
        if extra:
            assert admin_call(f'/{names[key]}/users/{user_id}', 'PUT', extra)[0] == 204
        return user_id, login

    def auth_page(label, key, headers=None, extra=None, cookies=None):
        browser = Browser(key, cookies)
        observations[label] = shown(browser.authorize(headers=headers, extra=extra), browser)

    def errors(body):
        text = body.decode()
        found = re.findall(r'<(\w+)[^>]*\bid="input-error-(?!container-)([a-zA-Z-]+)"[^>]*>(.*?)</\1>', text, re.S)
        return {name: ' '.join(re.sub(r'<[^>]+>', ' ', message).split()) for _, name, message in found}

    def profile_form(response):
        forms = Forms()
        forms.feed(response[2].decode())
        form = forms.forms[0]
        return {'form': form['id'], 'fields': sorted(form['fields']), 'disabled': sorted(disabled_names(response[2])), 'values': {name: form['fields'][name] for name in ('username', 'email') if name in form['fields']}}

    def admin_user(key, user_id):
        _, rep = admin_call(f'/{names[key]}/users/{user_id}')
        return [rep['username'], rep.get('email')]

    try:
        # The page locale on the authorization endpoint's login page.
        auth_page('auth/i18n/no-header', 'i18n')
        auth_page('auth/i18n/accept-fr', 'i18n', {'Accept-Language': 'fr'})
        auth_page('auth/i18n/accept-ar', 'i18n', {'Accept-Language': 'ar'})
        auth_page('auth/i18n/accept-fa', 'i18n', {'Accept-Language': 'fa-IR'})
        auth_page('auth/i18n/accept-he', 'i18n', {'Accept-Language': 'he'})
        auth_page('auth/i18n/accept-pt', 'i18n', {'Accept-Language': 'pt'})
        auth_page('auth/i18n/accept-unsupported', 'i18n', {'Accept-Language': 'it'})
        auth_page('auth/i18n/ui-locales', 'i18n', {'Accept-Language': 'fr'}, {'ui_locales': 'it ja'})
        auth_page('auth/i18n/ui-locales-unsupported', 'i18n', {'Accept-Language': 'fr'}, {'ui_locales': 'it'})
        auth_page('auth/i18n/ui-locales-over-cookie', 'i18n', None, {'ui_locales': 'ja'}, {'KEYCLOAK_LOCALE': 'fr'})
        auth_page('auth/i18n/cookie', 'i18n', {'Accept-Language': 'ja'}, None, {'KEYCLOAK_LOCALE': 'fr'})
        auth_page('auth/i18n/cookie-unsupported', 'i18n', {'Accept-Language': 'ja'}, None, {'KEYCLOAK_LOCALE': 'it'})
        auth_page('auth/i18n/kc-locale', 'i18n', {'Accept-Language': 'fr'}, {'kc_locale': 'ar', 'ui_locales': 'ja'})
        auth_page('auth/i18n/kc-locale-unsupported', 'i18n', {'Accept-Language': 'fr'}, {'kc_locale': 'it'})
        auth_page('auth/pair/no-header', 'pair')
        auth_page('auth/pair/accept-fr', 'pair', {'Accept-Language': 'fr'})
        auth_page('auth/pair/accept-de', 'pair', {'Accept-Language': 'de'})
        auth_page('auth/off/accept-de', 'off', {'Accept-Language': 'de'}, {'kc_locale': 'de', 'ui_locales': 'de'})
        auth_page('auth/plain/accept-de', 'plain', {'Accept-Language': 'de'})

        # The locale stays with the request across the login form.
        _, login = new_user('i18n', 'failed')
        for label, extra, query in (('ui-locales', {'ui_locales': 'ja'}, None), ('kc-locale', {'kc_locale': 'ar'}, None), ('kc-locale-on-form', None, {'kc_locale': 'fr'})):
            browser = Browser('i18n')
            page = browser.authorize(extra=extra)
            browser.cookies.pop('KEYCLOAK_LOCALE', None)
            response = browser.submit(page, {'username': login, 'password': 'wrong', 'credentialId': ''}, None, query)
            observations[f'form/i18n/failed-{label}'] = shown(response, browser)

        # What a successful login does to the cookie and the user's locale.
        def finished(label, key, login, **options):
            browser, response = sign_in(key, login, **options)
            observations[label] = shown(response, browser) | {'stored': stored_locale(key, login)}

        _, login = new_user('i18n', 'kc-locale')
        finished('login/i18n/kc-locale', 'i18n', login, extra={'kc_locale': 'ar'})
        _, login = new_user('i18n', 'kc-locale-form')
        finished('login/i18n/kc-locale-on-form', 'i18n', login, query={'kc_locale': 'fr'})
        _, login = new_user('i18n', 'kc-locale-unsupported')
        finished('login/i18n/kc-locale-unsupported', 'i18n', login, extra={'kc_locale': 'it'})
        _, login = user_with_locale('i18n', 'has-locale', 'ja')
        finished('login/i18n/user-locale', 'i18n', login, headers={'Accept-Language': 'fr'})
        _, login = user_with_locale('i18n', 'same-locale', 'ja')
        finished('login/i18n/kc-locale-same', 'i18n', login, extra={'kc_locale': 'ja'})
        _, login = user_with_locale('i18n', 'other-locale', 'ja')
        finished('login/i18n/kc-locale-other', 'i18n', login, extra={'kc_locale': 'fr'})
        _, login = new_user('i18n', 'no-locale')
        finished('login/i18n/no-locale-cookie', 'i18n', login, cookies={'KEYCLOAK_LOCALE': 'fr'})
        _, login = new_user('i18n', 'ui-locales')
        finished('login/i18n/ui-locales', 'i18n', login, extra={'ui_locales': 'fr'})
        _, login = new_user('off', 'kc-locale')
        browser, response = sign_in('off', login, extra={'kc_locale': 'de'}, cookies={'KEYCLOAK_LOCALE': 'fr'})
        observations['login/off/kc-locale'] = shown(response, browser)

        # Required-action pages: the user's locale counts once they are known.
        _, login = user_with_locale('i18n', 'profile-fa', 'fa', {'requiredActions': ['UPDATE_PROFILE']})
        browser, response = sign_in('i18n', login, headers={'Accept-Language': 'fr'})
        observations['action/i18n/user-locale'] = shown(response, browser)
        _, login = user_with_locale('i18n', 'profile-ja', 'ja', {'requiredActions': ['UPDATE_PROFILE']})
        browser, response = sign_in('i18n', login, extra={'kc_locale': 'ar'})
        observations['action/i18n/kc-locale-over-user'] = shown(response, browser)
        _, login = new_user('i18n', 'profile-ui', {'requiredActions': ['UPDATE_PROFILE']})
        browser, response = sign_in('i18n', login, extra={'ui_locales': 'ja'})
        observations['action/i18n/ui-locales'] = shown(response, browser)
        response = browser.submit(response, {'firstName': '', 'lastName': 'User'}, {'Accept-Language': 'fr'})
        observations['action/i18n/ui-locales-error'] = shown(response, browser)
        _, login = new_user('off', 'profile', {'requiredActions': ['UPDATE_PROFILE']})
        browser, response = sign_in('off', login, headers={'Accept-Language': 'de'})
        observations['action/off/page'] = shown(response, browser)

        # UPDATE_PROFILE under each username setting; each case has its own user.
        admin_call(f'/{names["plain"]}/users', 'POST', {'username': 'other-user', 'enabled': True, 'email': 'other@example.invalid'})
        for key in ('edit', 'email', 'both'):
            admin_call(f'/{names[key]}/users', 'POST', {'username': 'other-user', 'enabled': True, 'email': 'other@example.invalid'})
        # Target names and emails are unique to each case, so no case collides
        # with what another left behind.
        cases = [
            ('same', {}),
            ('same-username', None),
            ('rename', {'username': 'profile-renamed-user'}),
            ('rename-upper', {'username': 'Profile-Renamed-Upper'}),
            ('taken-username', {'username': 'other-user'}),
            ('blank-username', {'username': ''}),
            ('new-email', {'email': 'profile-changed@example.invalid'}),
            ('taken-email', {'email': 'other@example.invalid'}),
            ('email-as-other-username', {'email': 'other-user'}),
        ]
        for key in ('plain', 'edit', 'email', 'both'):
            for case, fields in cases:
                user_id, login = new_user(key, 'profile-' + case, {'requiredActions': ['UPDATE_PROFILE']})
                before = admin_user(key, user_id)
                browser, page = sign_in(key, login)
                form = profile_form(page)
                if case == 'same':
                    observations[f'profile/{key}/page'] = form
                if fields is None:
                    fields = {'username': before[0]}
                response = browser.submit(page, {'firstName': 'Changed', 'lastName': 'User'} | fields)
                result = {'status': response[0], 'errors': errors(response[2]) if response[0] == 200 else {}, 'before': before, 'after': admin_user(key, user_id)}
                if response[0] == 200:
                    result['form'] = profile_form(response)['values']
                observations[f'profile/{key}/{case}'] = result

        # Admin user updates under each username setting.
        admin_cases = [
            ('rename', {'username': 'admin-renamed-user'}),
            ('rename-upper', {'username': 'Admin-Renamed-Upper'}),
            ('same-upper', None),
            ('taken-username', {'username': 'other-user'}),
            ('blank-username', {'username': ''}),
            ('null-username', {'username': None}),
            ('new-email', {'email': 'admin-changed@example.invalid'}),
            ('taken-email', {'email': 'other@example.invalid'}),
            ('email-as-other-username', {'email': 'other-user'}),
            ('username-and-email', {'username': 'admin-pair-user', 'email': 'admin-pair@example.invalid'}),
            ('clear-email', {'email': ''}),
        ]
        for key in ('plain', 'edit', 'email', 'both'):
            for case, payload in admin_cases:
                user_id, login = new_user(key, 'admin-' + case)
                before = admin_user(key, user_id)
                if payload is None:
                    payload = {'username': before[0].upper()}
                status, body = admin_call(f'/{names[key]}/users/{user_id}', 'PUT', payload)
                observations[f'admin/{key}/{case}'] = {'status': status, 'body': body, 'before': before, 'after': admin_user(key, user_id)}

        observations = json.loads(clean(json.dumps(observations)))
        baseline = pathlib.Path(__file__).with_name('login-settings-observations.json')
        assert record or baseline.exists(), 'reference login settings baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference login settings case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference login settings case changed: {label}: {observations[label]}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Realm internationalization on the login and UPDATE_PROFILE pages (html lang and dir from kc_locale, the user locale, ui_locales, KEYCLOAK_LOCALE and Accept-Language), the KEYCLOAK_LOCALE cookie and user locale set by login, and UPDATE_PROFILE and admin user updates under editUsernameAllowed and registrationEmailAsUsername.', 'normalization': 'The base URL and realm names are replaced with placeholders; pages are reduced to status, html lang and dir, locale cookies, form fields, disabled fields and error texts.', 'observations': observations}
    finally:
        for name in names.values():
            oauth.request(base + '/admin/realms/' + name, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference login settings check failed: {error}') from None
