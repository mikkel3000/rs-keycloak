#!/usr/bin/env python3
"""Capture pinned Keycloak's rememberMe.

Covers the login form's "Remember me" checkbox (login.ftl, shown with the
realm's rememberMe), what a checked sign-in does (AuthenticatorUtils.
processRememberMe and AuthenticationManager: the KEYCLOAK_REMEMBER_ME
cookie with "username:<encoded name>", the identity and session cookies'
Max-Age, the session's rememberMe flag), the refresh token's lifetime
with the remember-me idle and lifespan settings (RealmExpiration,
SessionExpirationUtils), how the cookie fills the username and checks the
box on a later login form (UsernamePasswordForm), and how an unchecked
sign-in removes it.
"""
import base64
import json
import urllib.parse

import oauth
from recording import Recording
from login_browser import forms  # noqa: E402

REALMS = {
    'on': {'rememberMe': True},
    'off': {},
    'lifespans': {'rememberMe': True, 'ssoSessionIdleTimeoutRememberMe': 3600, 'ssoSessionMaxLifespanRememberMe': 72000},
}
COOKIES = ('KEYCLOAK_IDENTITY', 'KEYCLOAK_SESSION', 'KEYCLOAK_REMEMBER_ME')


def claims(token):
    payload = token.split('.')[1]
    return json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))


def cookies(browser):
    """The login cookies a response chain set: the remember-me value, and
    for each cookie its attributes without Expires."""
    result = {}
    for value in browser.set_cookies:
        name, _, rest = value.partition('=')
        if name not in COOKIES:
            continue
        content, *attributes = [part.strip() for part in rest.split(';')]
        kept = sorted(attribute for attribute in attributes if not attribute.lower().startswith('expires') and attribute)
        result[name] = {'value': content if name == 'KEYCLOAK_REMEMBER_ME' else bool(content), 'attributes': kept}
    return result


def run(base, bootstrap_secret, record=False):
    rec = Recording(base, bootstrap_secret, REALMS)
    observations = {}
    rec.create_realms(REALMS)

    def login_form(browser, query=None):
        page = browser.authorize(query)
        form = next(form for form in forms(page[2]) if form['id'] == 'kc-form-login')
        return browser.shown(page) | {'username_value': form['fields'].get('username'), 'checkboxes': form['checkboxes']}

    def signed_in(key, username, checked, browser=None):
        browser = browser or rec.browser(key)
        response = browser.sign_in(username, rec.password, checked=('rememberMe',) if checked else ())
        result = browser.shown(response) | {'cookies': cookies(browser)}
        tokens = browser.exchange(response)
        refresh = claims(tokens['refresh_token'])
        result['refresh_lifetime'] = refresh['exp'] - refresh['iat']
        # refresh_expires_in counts from the response, a second later at most.
        result['refresh_expires_in_matches'] = 0 <= result['refresh_lifetime'] - tokens['refresh_expires_in'] <= 2
        _, user = rec.admin_call(key, '/users?exact=true&username=' + urllib.parse.quote(username))
        _, sessions = rec.admin_call(key, f'/users/{user[0]["id"]}/sessions')
        result['session_remember_me'] = sorted(session['rememberMe'] for session in sessions)
        return result, browser

    try:
        for key in REALMS:
            _, realm = rec.admin_call(key, '')
            observations[f'representation/{key}'] = {field: realm.get(field) for field in ('rememberMe', 'ssoSessionIdleTimeoutRememberMe', 'ssoSessionMaxLifespanRememberMe', 'ssoSessionIdleTimeout', 'ssoSessionMaxLifespan')}
            observations[f'login-form/{key}'] = login_form(rec.browser(key))

        for key in REALMS:
            rec.new_user(key, 'checked-user')
            rec.new_user(key, 'unchecked-user')
            observations[f'sign-in/{key}/checked'], _ = signed_in(key, 'checked-user', True)
            observations[f'sign-in/{key}/unchecked'], _ = signed_in(key, 'unchecked-user', False)

        # The cookie names the username encoded as a form value.
        rec.new_user('on', 'remember+user')
        observations['sign-in/on/encoded-name'], remembered = signed_in('on', 'remember+user', True)

        # A later login form in a browser with only the remember-me cookie.
        cookie = {'KEYCLOAK_REMEMBER_ME': remembered.cookies['KEYCLOAK_REMEMBER_ME']}
        for key in ('on', 'off'):
            browser = rec.browser(key)
            browser.cookies = dict(cookie)
            observations[f'prefilled/{key}'] = login_form(browser)
        browser = rec.browser('on')
        browser.cookies = dict(cookie)
        observations['prefilled/on/login-hint'] = login_form(browser, {'login_hint': 'hinted-user'})
        browser = rec.browser('on')
        browser.cookies = {'KEYCLOAK_REMEMBER_ME': 'name:remember-user'}
        observations['prefilled/on/other-prefix'] = login_form(browser)

        # Signing in unchecked from a remembered browser removes the cookie.
        browser = rec.browser('on')
        browser.cookies = dict(cookie)
        observations['sign-in/on/unchecked-after-remembered'], _ = signed_in('on', 'remember+user', False, browser)
    finally:
        rec.delete_realms()
    return rec.finish(observations, 'remember-me-observations.json', record,
                      'rememberMe: the login form checkbox, the cookies a checked or unchecked sign-in sets, the refresh token lifetime with the remember-me idle and lifespan settings, the session flag, the username and checkbox a remembered browser sees, and removal by an unchecked sign-in.',
                      'The base URL and realm names are replaced with placeholders; pages are reduced by tests/page_texts.py without the language choice, with their form ids; cookies keep their attributes without Expires, and only the remember-me cookie keeps its value; tokens keep exp minus iat of the refresh token and whether refresh_expires_in is within two seconds of it.')


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        raise SystemExit(f'reference rememberMe check failed: {error}') from None
