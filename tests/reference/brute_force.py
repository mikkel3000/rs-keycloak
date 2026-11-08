#!/usr/bin/env python3
"""Capture pinned Keycloak's brute-force detection on the login form.

Covers the realm settings and their defaults, failure counting and
temporary lockout after failureFactor failures (DefaultBruteForceProtector
with the MULTIPLE strategy), the quick-login lockout, a locked user's
correct password being refused with the same message
(AbstractUsernameFormAuthenticator.isDisabledByBruteForce), permanent
lockout disabling the user, the attack-detection admin endpoints, and a
realm without detection, which never locks.
"""
import time

import oauth
from recording import Recording

REALMS = {
    'off': {},
    'protected': {'bruteForceProtected': True, 'failureFactor': 2},
    'quick': {'bruteForceProtected': True},
    'permanent': {'bruteForceProtected': True, 'permanentLockout': True, 'failureFactor': 2},
}
FIELDS = ('bruteForceProtected', 'permanentLockout', 'maxTemporaryLockouts', 'bruteForceStrategy', 'maxFailureWaitSeconds', 'minimumQuickLoginWaitSeconds', 'waitIncrementSeconds', 'quickLoginCheckMilliSeconds', 'maxDeltaTimeSeconds', 'failureFactor')


def run(base, bootstrap_secret, record=False):
    rec = Recording(base, bootstrap_secret, REALMS)
    observations = {}
    rec.create_realms(REALMS)

    def attempt(key, username, password):
        browser = rec.browser(key)
        return browser.shown(browser.sign_in(username, password))

    def status_of(key, user_id):
        # The reference counts failures on its own executor.
        time.sleep(0.2)
        status, found = rec.admin_call(key, f'/attack-detection/brute-force/users/{user_id}')
        if not isinstance(found, dict):
            return {'status': status}
        result = {'status': status} | {field: found.get(field) for field in ('disabled', 'numFailures', 'numTemporaryLockouts', 'numSecondaryAuthFailures')}
        result['lastFailure'] = found.get('lastFailure', 0) > 0
        result['lastIPFailure'] = found.get('lastIPFailure') if found.get('lastIPFailure') == 'n/a' else 'ip'
        result['locked_until'] = 'none' if not found.get('failedLoginNotBefore') else 'permanent' if found['failedLoginNotBefore'] >= 2 ** 63 - 1 else 'later'
        result['fields'] = sorted(found)
        return result

    try:
        for key in ('off', 'protected'):
            _, realm = rec.admin_call(key, '')
            observations[f'representation/{key}'] = {field: realm.get(field) for field in FIELDS}

        # Without detection nothing locks.
        user = rec.new_user('off', 'off-user')
        for number in range(6):
            observations[f'off/wrong-{number}'] = attempt('off', 'off-user', 'wrong')
        observations['off/right'] = attempt('off', 'off-user', rec.password)
        observations['off/status'] = status_of('off', user)

        # failureFactor 2: the second failure locks for waitIncrementSeconds.
        user = rec.new_user('protected', 'locked-user')
        observations['protected/status-before'] = status_of('protected', user)
        observations['protected/wrong-1'] = attempt('protected', 'locked-user', 'wrong')
        observations['protected/status-1'] = status_of('protected', user)
        observations['protected/wrong-2'] = attempt('protected', 'locked-user', 'wrong')
        observations['protected/status-2'] = status_of('protected', user)
        observations['protected/right-while-locked'] = attempt('protected', 'locked-user', rec.password)
        observations['protected/status-after-right'] = status_of('protected', user)
        _, stored = rec.admin_call('protected', f'/users/{user}')
        observations['protected/user-enabled'] = stored['enabled']
        status, _ = rec.admin_call('protected', f'/attack-detection/brute-force/users/{user}', 'DELETE')
        observations['protected/clear-user'] = {'status': status} | {'after': status_of('protected', user)}
        observations['protected/right-after-clear'] = attempt('protected', 'locked-user', rec.password)
        # A success clears the count.
        observations['protected/wrong-after-success'] = attempt('protected', 'locked-user', 'wrong')
        observations['protected/right-after-one'] = attempt('protected', 'locked-user', rec.password)
        observations['protected/status-after-success'] = status_of('protected', user)
        # Unknown users count nothing and answer as a wrong password.
        observations['protected/unknown-user'] = attempt('protected', 'nobody', 'wrong')
        observations['protected/status-unknown-id'] = status_of('protected', '00000000-0000-0000-0000-000000000000')
        # Clearing every user.
        other = rec.new_user('protected', 'other-user')
        attempt('protected', 'other-user', 'wrong')
        attempt('protected', 'other-user', 'wrong')
        status, _ = rec.admin_call('protected', '/attack-detection/brute-force/users', 'DELETE')
        observations['protected/clear-all'] = {'status': status, 'after': status_of('protected', other)}
        observations['protected/right-after-clear-all'] = attempt('protected', 'other-user', rec.password)

        # Two failures within quickLoginCheckMilliSeconds lock for
        # minimumQuickLoginWaitSeconds.
        user = rec.new_user('quick', 'quick-user')
        observations['quick/wrong-1'] = attempt('quick', 'quick-user', 'wrong')
        observations['quick/wrong-2'] = attempt('quick', 'quick-user', 'wrong')
        observations['quick/status'] = status_of('quick', user)
        observations['quick/right-while-locked'] = attempt('quick', 'quick-user', rec.password)

        # Permanent lockout disables the user until an admin enables them.
        user = rec.new_user('permanent', 'permanent-user')
        observations['permanent/wrong-1'] = attempt('permanent', 'permanent-user', 'wrong')
        observations['permanent/wrong-2'] = attempt('permanent', 'permanent-user', 'wrong')
        observations['permanent/status'] = status_of('permanent', user)
        _, stored = rec.admin_call('permanent', f'/users/{user}')
        observations['permanent/user'] = {'enabled': stored['enabled'], 'attributes': stored.get('attributes')}
        observations['permanent/right'] = attempt('permanent', 'permanent-user', rec.password)
        status, _ = rec.admin_call('permanent', f'/users/{user}', 'PUT', {'enabled': True})
        observations['permanent/enabled-again'] = {'status': status, 'after': status_of('permanent', user)}
        observations['permanent/right-after-enable'] = attempt('permanent', 'permanent-user', rec.password)
    finally:
        rec.delete_realms()
    return rec.finish(observations, 'brute-force-observations.json', record,
                      'Brute-force detection: the realm settings and defaults, failure counts, temporary, quick and permanent lockouts on the login form, the attack-detection admin endpoints, and a realm without detection.',
                      'The base URL and realm names are replaced with placeholders; pages are reduced by tests/page_texts.py without the language choice, with their form ids; redirects keep their path and whether they carry a code; attack-detection answers keep their flags and counts, whether a last failure and IP are known, whether the lock ends later or never, and their field names.')


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        raise SystemExit(f'reference brute force check failed: {error}') from None
