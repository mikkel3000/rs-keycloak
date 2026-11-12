#!/usr/bin/env python3
"""Capture pinned Keycloak's realm OTP policy.

Covers the policy fields of the realm representation and their defaults,
what a partial update keeps (DefaultExportImportManager.toPolicy: a
policy is read only with its type), and the CONFIGURE_TOTP manual mode
under each policy (login-config-totp.ftl's policy items and the
supported applications of the OTPApplicationProviders). The QR code's key
URI and the code checks are in otp_codes.py.
"""
import re

import oauth
from recording import Recording
from otp_codes import FULL, REALMS as CODE_REALMS, setup_page

REALMS = CODE_REALMS | {
    'untyped':{'otpPolicyAlgorithm': 'HmacSHA256', 'otpPolicyDigits': 8, 'otpPolicyCodeReusable': True},
    'typed-alone': {'otpPolicyType': 'hotp'},
    'partial': {},
}
FIELDS = ('otpPolicyType', 'otpPolicyAlgorithm', 'otpPolicyInitialCounter', 'otpPolicyDigits', 'otpPolicyLookAheadWindow', 'otpPolicyPeriod', 'otpPolicyCodeReusable', 'otpSupportedApplications')


def run(base, bootstrap_secret, record=False):
    rec = Recording(base, bootstrap_secret, REALMS)
    observations = {}
    rec.create_realms(REALMS)

    def policy(key):
        _, realm = rec.admin_call(key, '')
        return {field: realm.get(field) for field in FIELDS}

    try:
        for key in ('default', 'sha256', 'hotp', 'reusable', 'untyped', 'typed-alone'):
            observations[f'representation/{key}'] = policy(key)
        status, _ = rec.admin_call('partial', '', 'PUT', {'otpPolicyType': 'totp', 'otpPolicyDigits': 8})
        observations['partial-update'] = {'status': status} | policy('partial')
        status, _ = rec.admin_call('partial', '', 'PUT', {'otpPolicyDigits': 6})
        observations['update-without-type'] = {'status': status} | policy('partial')
        status, _ = rec.admin_call('partial', '', 'PUT', {'otpPolicyType': 'totp', 'otpPolicyAlgorithm': 'HmacSHA1', 'otpPolicyDigits': 6, 'otpPolicyPeriod': 30, 'otpPolicyLookAheadWindow': 1, 'otpPolicyInitialCounter': 0})
        observations['full-update'] = {'status': status} | policy('partial')

        # The manual setup mode's policy items and the listed apps under
        # each policy; otp_codes.py records the QR code's key URI.
        for key in ('default', 'sha256', 'sha512', 'hotp'):
            rec.new_user(key, 'page-user', {'requiredActions': ['CONFIGURE_TOTP']})
            browser = rec.browser(key)
            page = browser.sign_in('page-user', rec.password)
            manual = browser.visit(re.search(r'<a href="([^"]*)" id="mode-manual"', page[2].decode()).group(1))
            observations[f'setup-manual/{key}'], _ = setup_page(browser, manual)
    finally:
        rec.delete_realms()
    return rec.finish(observations, 'otp-policy-observations.json', record,
                      'The realm OTP policy: its representation fields and defaults, partial and full updates, and the manual setup mode with the policy and the supported apps under TOTP and HOTP policies with other algorithms, digits and periods. otp_codes.py records the key URIs and code checks.',
                      'The base URL and realm names are replaced with placeholders; pages are reduced by tests/page_texts.py without the language choice, with their form ids and list items sorted and the shown key as {key}.')


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        raise SystemExit(f'reference OTP policy check failed: {error}') from None
