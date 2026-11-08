#!/usr/bin/env python3
"""Capture pinned Keycloak's registration page.

Covers registrationAllowed: the login page's "Register" link (login.ftl),
the registration form (register.ftl with the default user profile's
fields), its validation in order (RegistrationUserCreation with the
REGISTRATION user profile, then RegistrationPassword), the user a passing
submission makes and signs in, registrationEmailAsUsername, the "Back to
Login" link, and the error page of a realm without registration.
"""
import re
import urllib.parse

import oauth
from recording import Recording
from login_browser import forms  # noqa: E402

REALMS = {
    'open': {'registrationAllowed': True},
    'closed': {},
    'email': {'registrationAllowed': True, 'registrationEmailAsUsername': True},
}
FIELDS = ('username', 'email', 'firstName', 'lastName', 'password', 'password-confirm')


def run(base, bootstrap_secret, record=False):
    rec = Recording(base, bootstrap_secret, REALMS)
    observations = {}
    rec.create_realms(REALMS)

    def register_link(page):
        found = re.search(r'href="([^"]*/login-actions/registration[^"]*)"', page[2].decode())
        return found.group(1) if found else None

    def form(browser, key):
        """A fresh registration form."""
        page = browser.authorize()
        return browser.visit(register_link(page))

    def post(key, values, browser=None):
        browser = browser or rec.browser(key)
        page = form(browser, key)
        response = browser.submit(page, values, form_id='kc-register-form')
        return browser, response

    def user(key, username):
        _, found = rec.admin_call(key, '/users?exact=true&username=' + urllib.parse.quote(username))
        return [{field: entry.get(field) for field in ('username', 'email', 'firstName', 'lastName', 'enabled', 'emailVerified', 'requiredActions')} for entry in found]

    valid = {'username': 'new-user', 'email': 'new-user@example.invalid', 'firstName': 'Given', 'lastName': 'Family', 'password': rec.password, 'password-confirm': rec.password}
    try:
        for key in REALMS:
            _, realm = rec.admin_call(key, '')
            observations[f'representation/{key}'] = {'registrationAllowed': realm.get('registrationAllowed')}
            browser = rec.browser(key)
            page = browser.authorize()
            link = register_link(page)
            observations[f'login-form/{key}'] = browser.shown(page) | {'register_link': bool(link)}
            if link:
                registration = browser.visit(link)
                fields = next(found for found in forms(registration[2]) if found['id'] == 'kc-register-form')['fields']
                observations[f'form/{key}'] = browser.shown(registration) | {'fields': [name for name in fields if name in FIELDS]}
                back = re.search(r'<a[^>]*href="([^"]*)"[^>]*>[^<]*Back to Login', registration[2].decode())
                observations[f'back-to-login/{key}'] = browser.shown(browser.visit(back.group(1))) if back else None

        # A realm without registration answers the registration URL with an
        # error page.
        browser = rec.browser('closed')
        page = browser.authorize()
        action = urllib.parse.urlsplit(re.search(r'action="([^"]*)"', page[2].decode()).group(1).replace('&amp;', '&'))
        query = urllib.parse.parse_qs(action.query)
        target = f'/realms/{rec.names["closed"]}/login-actions/registration?' + urllib.parse.urlencode({name: query[name][0] for name in ('client_id', 'tab_id') if name in query})
        observations['closed/registration-url'] = browser.shown(browser.send(target))

        rec.new_user('open', 'taken-user', {'email': 'taken@example.invalid'})
        failing = {
            'empty': {name: '' for name in FIELDS},
            'short-username': valid | {'username': 'ab'},
            'bad-username': valid | {'username': 'bad name<'},
            'bad-email': valid | {'email': 'not-an-email'},
            'bad-names': valid | {'firstName': 'Given<', 'lastName': 'x' * 256},
            'taken-username': valid | {'username': 'Taken-User'},
            'taken-email': valid | {'email': 'TAKEN@example.invalid'},
            'taken-both': valid | {'username': 'taken-user', 'email': 'taken@example.invalid'},
            'no-password': valid | {'password': '', 'password-confirm': ''},
            'mismatch': valid | {'password-confirm': rec.password + 'x'},
            'mismatch-and-bad-email': valid | {'email': 'nope', 'password-confirm': 'other'},
        }
        for label, values in failing.items():
            browser, response = post('open', values)
            observations[f'failing/{label}'] = browser.shown(response) | {'kept': {name: value for name, value in forms(response[2])[0]['fields'].items() if name in FIELDS} if response[0] == 200 else None}
            observations[f'failing/{label}/created'] = user('open', values['username'].lower()) if values['username'] else []

        browser, response = post('open', valid)
        observations['passing/open'] = browser.shown(response)
        observations['passing/open/user'] = user('open', 'new-user')
        observations['passing/open/sign-in'] = rec.browser('open').shown(rec.browser('open').sign_in('new-user', rec.password))
        browser, response = post('open', valid | {'username': 'Mixed.Case', 'email': 'Mixed.Case@Example.Invalid'})
        observations['passing/open/mixed-case'] = browser.shown(response)
        observations['passing/open/mixed-case/user'] = user('open', 'mixed.case')

        email_valid = {name: value for name, value in valid.items() if name != 'username'} | {'email': 'Email.User@example.invalid'}
        browser, response = post('email', email_valid)
        observations['passing/email'] = browser.shown(response)
        observations['passing/email/user'] = user('email', 'email.user@example.invalid')
        browser, response = post('email', email_valid)
        observations['failing/email/taken'] = browser.shown(response)
        browser, response = post('email', email_valid | {'email': ''})
        observations['failing/email/empty'] = browser.shown(response)
    finally:
        rec.delete_realms()
    return rec.finish(observations, 'registration-observations.json', record,
                      'registrationAllowed: the login page link, the registration form and its fields, each validation failure with the values kept, passing registrations and the users they make, registrationEmailAsUsername, the back-to-login link, and the registration URL of a realm without registration.',
                      'The base URL and realm names are replaced with placeholders; pages are reduced by tests/page_texts.py without the language choice, with their form ids and the profile and password field names and kept values; redirects keep their path and whether they carry a code; users keep their profile fields, flags and required actions.')


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        raise SystemExit(f'reference registration check failed: {error}') from None
