#!/usr/bin/env python3
"""Capture pinned Keycloak's VERIFY_PROFILE required action.

Covers VerifyUserProfile: the action is on in a new realm and fires at
login for a user the default user profile finds incomplete (firstName,
lastName and email are required for users), without being added to the
user; the form it shows with its field errors, a failed and a passing
submission, and a realm with the action turned off.
"""
import oauth
from recording import Recording

REALMS = {'default': {}, 'off': {}, 'edit': {'editUsernameAllowed': True}}


def run(base, bootstrap_secret, record=False):
    rec = Recording(base, bootstrap_secret, REALMS)
    observations = {}
    rec.create_realms(REALMS)
    try:
        status, action = rec.admin_call('off', '/authentication/required-actions/VERIFY_PROFILE')
        observations['action/default'] = {'status': status, 'enabled': action['enabled'], 'defaultAction': action['defaultAction'], 'priority': action['priority']}
        status, _ = rec.admin_call('off', '/authentication/required-actions/VERIFY_PROFILE', 'PUT', action | {'enabled': False})
        observations['action/turned-off'] = {'status': status}

        cases = {
            'complete': {},
            'no-first-name': {'firstName': None},
            'no-last-name-email': {'lastName': None, 'email': None},
            'nothing': {'firstName': None, 'lastName': None, 'email': None},
        }
        for label, missing in cases.items():
            for key in ('default', 'off'):
                username = f'{label}-{key}'
                user_id = rec.new_user(key, username, missing)
                browser = rec.browser(key)
                page = browser.sign_in(username, rec.password)
                observations[f'sign-in/{label}/{key}'] = browser.shown(page)
                _, stored = rec.admin_call(key, f'/users/{user_id}')
                observations[f'user-while-pending/{label}/{key}'] = {'requiredActions': stored['requiredActions']}
                if key == 'default' and label != 'complete':
                    observations[f'empty-post/{label}'] = browser.shown(page := browser.submit(page, {'firstName': '', 'lastName': '', 'email': ''}))
                    observations[f'bad-email/{label}'] = browser.shown(page := browser.submit(page, {'firstName': 'Given', 'lastName': 'Family', 'email': 'not-an-email'}))
                    observations[f'passing/{label}'] = browser.shown(browser.submit(page, {'firstName': 'Given', 'lastName': 'Family', 'email': f'new-{label}@example.invalid'}))
                    _, stored = rec.admin_call(key, f'/users/{user_id}')
                    observations[f'user-after/{label}'] = {field: stored.get(field) for field in ('firstName', 'lastName', 'email', 'emailVerified', 'requiredActions')}
                    observations[f'sign-in-again/{label}'] = browser.shown(rec.browser(key).sign_in(username, rec.password))

        # With usernames editable the form shows the username too.
        rec.new_user('edit', 'edit-user', {'firstName': None})
        rec.new_user('edit', 'taken-user')
        browser = rec.browser('edit')
        page = browser.sign_in('edit-user', rec.password)
        observations['sign-in/edit'] = browser.shown(page)
        observations['taken-username/edit'] = browser.shown(page := browser.submit(page, {'username': 'taken-user', 'firstName': 'Given', 'lastName': 'Family'}))
        observations['renamed/edit'] = browser.shown(browser.submit(page, {'username': 'renamed-user', 'firstName': 'Given', 'lastName': 'Family'}))
        # UPDATE_PROFILE and an incomplete profile show the form once.
        rec.new_user('default', 'both-user', {'firstName': None, 'requiredActions': ['UPDATE_PROFILE']})
        browser = rec.browser('default')
        page = browser.sign_in('both-user', rec.password)
        observations['sign-in/update-profile-too'] = browser.shown(page)
        observations['passing/update-profile-too'] = browser.shown(browser.submit(page, {'firstName': 'Given', 'lastName': 'Family'}))
    finally:
        rec.delete_realms()
    return rec.finish(observations, 'verify-profile-observations.json', record,
                      'VERIFY_PROFILE: its default setting, when it fires at login for users missing required profile fields, the form and its field errors, failed and passing submissions, the username with editUsernameAllowed, together with UPDATE_PROFILE, and a realm with it turned off.',
                      'The base URL and realm names are replaced with placeholders; pages are reduced by tests/page_texts.py without the language choice, with their form ids; redirects keep their path and whether they carry a code.')


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        raise SystemExit(f'reference VERIFY_PROFILE check failed: {error}') from None
