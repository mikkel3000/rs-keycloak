#!/usr/bin/env python3
"""Capture pinned Keycloak's realm OTP policy.

Covers the policy fields of the realm representation and their defaults,
what a partial update keeps (DefaultExportImportManager.toPolicy), the
CONFIGURE_TOTP page under each policy (the key URI of OTPPolicy.getKeyURI
in its QR code, the manual mode's policy items, the supported
applications), which codes setup and the code form accept (TimeBasedOTP
with the look-ahead window either side, HmacOTP forward from the stored
counter, which setup moves past the code it accepted), a credential
keeping the policy it was made with, and code reuse with
otpPolicyCodeReusable.
"""
import base64
import re

import oauth
from recording import Recording
from login_browser import base32, forms, hotp, totp  # noqa: E402
import qr_code  # noqa: E402

# The reference reads a policy given at creation only with its type, and
# then takes missing fields as 0 or null, so each policy is given whole.
FULL = {'otpPolicyType': 'totp', 'otpPolicyAlgorithm': 'HmacSHA1', 'otpPolicyDigits': 6, 'otpPolicyPeriod': 30, 'otpPolicyLookAheadWindow': 1, 'otpPolicyInitialCounter': 0}
REALMS = {
    'default': {},
    'sha256': FULL | {'otpPolicyAlgorithm': 'HmacSHA256', 'otpPolicyDigits': 8, 'otpPolicyPeriod': 60},
    'sha512': FULL | {'otpPolicyAlgorithm': 'HmacSHA512', 'otpPolicyLookAheadWindow': 0},
    'hotp': FULL | {'otpPolicyType': 'hotp', 'otpPolicyInitialCounter': 5, 'otpPolicyLookAheadWindow': 2},
    'reusable': FULL | {'otpPolicyCodeReusable': True},
    'untyped': {'otpPolicyAlgorithm': 'HmacSHA256', 'otpPolicyDigits': 8, 'otpPolicyCodeReusable': True},
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

    def setup_page(response):
        """The setup page's texts, key URI, policy items and applications."""
        text = response[2].decode()
        result = rec.browser('default').shown(response)
        fields = next((form['fields'] for form in forms(response[2]) if 'totpSecret' in form['fields']), None)
        if fields is None:
            return result, None
        secret = fields['totpSecret']
        encoded = base32(secret.encode())
        grouped = ' '.join(encoded[i:i + 4] for i in range(0, len(encoded), 4))
        result['items'] = sorted(item.replace(grouped, '{key}') for item in result.get('items', []))
        image = re.search(r'<img[^>]*id="kc-totp-secret-qr-code"[^>]*src="data:image/png;base64,\s*([^"]+)"', text)
        if image:
            result['key_uri'] = qr_code.read(base64.b64decode(image.group(1)))['text'].replace(base32(secret.encode()), '{secret}')
        return result, secret

    def set_up(key, username, code_of):
        """Signs in a user with CONFIGURE_TOTP and posts the code
        `code_of(secret)`; returns the page, the response and the secret."""
        rec.new_user(key, username, {'requiredActions': ['CONFIGURE_TOTP']})
        browser = rec.browser(key)
        page = browser.sign_in(username, rec.password)
        shown, secret = setup_page(page)
        return shown, browser.shown(browser.submit(page, {'totp': code_of(secret), 'userLabel': ''})), secret

    def code_form(key, username, code):
        browser = rec.browser(key)
        page = browser.sign_in(username, rec.password)
        return browser.shown(browser.submit(page, {'otp': code}))

    try:
        for key in ('default', 'sha256', 'hotp', 'reusable', 'untyped', 'typed-alone'):
            observations[f'representation/{key}'] = policy(key)
        status, _ = rec.admin_call('partial', '', 'PUT', {'otpPolicyType': 'totp', 'otpPolicyDigits': 8})
        observations['partial-update'] = {'status': status} | policy('partial')
        status, _ = rec.admin_call('partial', '', 'PUT', {'otpPolicyDigits': 6})
        observations['update-without-type'] = {'status': status} | policy('partial')
        status, _ = rec.admin_call('partial', '', 'PUT', {'otpPolicyType': 'totp', 'otpPolicyAlgorithm': 'HmacSHA1', 'otpPolicyDigits': 6, 'otpPolicyPeriod': 30, 'otpPolicyLookAheadWindow': 1, 'otpPolicyInitialCounter': 0})
        observations['full-update'] = {'status': status} | policy('partial')

        # Setup under each policy, with the manual mode's items.
        for key in ('default', 'sha256', 'sha512', 'hotp'):
            rec.new_user(key, 'page-user', {'requiredActions': ['CONFIGURE_TOTP']})
            browser = rec.browser(key)
            page = browser.sign_in('page-user', rec.password)
            observations[f'setup/{key}'], _ = setup_page(page)
            manual = browser.visit(re.search(r'<a href="([^"]*)" id="mode-manual"', page[2].decode()).group(1))
            observations[f'setup-manual/{key}'], _ = setup_page(manual)

        # Which codes setup accepts.
        cases = {
            'sha256/now': ('sha256', lambda s: totp(s, 0, 8, 60, 'HmacSHA256')),
            'sha256/previous-step': ('sha256', lambda s: totp(s, -1, 8, 60, 'HmacSHA256')),
            'sha256/two-steps-ahead': ('sha256', lambda s: totp(s, 2, 8, 60, 'HmacSHA256')),
            'sha256/six-digits': ('sha256', lambda s: totp(s, 0, 8, 60, 'HmacSHA256')[2:]),
            'sha256/sha1-code': ('sha256', lambda s: totp(s, 0, 8, 60)),
            'sha512/now': ('sha512', lambda s: totp(s, 0, 6, 30, 'HmacSHA512')),
            'sha512/previous-step': ('sha512', lambda s: totp(s, -1, 6, 30, 'HmacSHA512')),
            'hotp/initial-counter': ('hotp', lambda s: hotp(s, 5)),
            'hotp/look-ahead-end': ('hotp', lambda s: hotp(s, 7)),
            'hotp/past-look-ahead': ('hotp', lambda s: hotp(s, 8)),
            'hotp/before-counter': ('hotp', lambda s: hotp(s, 4)),
        }
        secrets_of = {}
        for label, (key, code_of) in cases.items():
            username = 'setup-' + label.replace('/', '-')
            _, observations[f'setup-code/{label}'], secrets_of[label] = set_up(key, username, code_of)

        # The code form after setup.
        secret = secrets_of['hotp/initial-counter']
        observations['code/hotp/same-code'] = code_form('hotp', 'setup-hotp-initial-counter', hotp(secret, 5))
        observations['code/hotp/next-counter'] = code_form('hotp', 'setup-hotp-initial-counter', hotp(secret, 6))
        observations['code/hotp/skips-ahead'] = code_form('hotp', 'setup-hotp-initial-counter', hotp(secret, 9))
        observations['code/hotp/behind'] = code_form('hotp', 'setup-hotp-initial-counter', hotp(secret, 8))
        secret = secrets_of['hotp/look-ahead-end']
        observations['code/hotp/after-look-ahead-end'] = code_form('hotp', 'setup-hotp-look-ahead-end', hotp(secret, 8))
        secret = secrets_of['sha256/now']
        observations['code/sha256/now'] = code_form('sha256', 'setup-sha256-now', totp(secret, 1, 8, 60, 'HmacSHA256'))
        observations['code/sha256/previous-step'] = code_form('sha256', 'setup-sha256-now', totp(secret, -1, 8, 60, 'HmacSHA256'))

        # A credential keeps the policy it was made with.
        _, observations['setup-code/default/for-policy-change'], secret = set_up('default', 'kept-user', lambda s: totp(s))
        _, user = rec.admin_call('default', '/users?exact=true&username=kept-user')
        _, credentials = rec.admin_call('default', f'/users/{user[0]["id"]}/credentials')
        observations['credential-data/default'] = sorted((credential['type'], credential.get('credentialData')) for credential in credentials)
        status, _ = rec.admin_call('default', '', 'PUT', {'otpPolicyType': 'totp', 'otpPolicyAlgorithm': 'HmacSHA256', 'otpPolicyDigits': 8, 'otpPolicyPeriod': 30, 'otpPolicyLookAheadWindow': 1, 'otpPolicyInitialCounter': 0})
        observations['code/default/after-policy-change'] = code_form('default', 'kept-user', totp(secret, 1))

        # Reusing a code.
        # The default realm's policy is now HmacSHA256 with 8 digits.
        for key, digits, algorithm in (('default', 8, 'HmacSHA256'), ('reusable', 6, 'HmacSHA1')):
            username = 'reuse-' + key
            _, observations[f'setup-code/{key}/reuse'], secret = set_up(key, username, lambda s: totp(s, -1, digits, 30, algorithm))
            code = totp(secret, 0, digits, 30, algorithm)
            observations[f'code/{key}/first-use'] = code_form(key, username, code)
            observations[f'code/{key}/second-use'] = code_form(key, username, code)
    finally:
        rec.delete_realms()
    return rec.finish(observations, 'otp-policy-observations.json', record,
                      'The realm OTP policy: its representation fields and defaults, partial and full updates, the CONFIGURE_TOTP page and key URI under TOTP and HOTP policies with other algorithms, digits and periods, which setup and login codes the look-ahead window and HOTP counter accept, a credential keeping its policy, and code reuse.',
                      'The base URL and realm names are replaced with placeholders; pages are reduced by tests/page_texts.py without the language choice, with their form ids and list items sorted; the QR code is read into its key URI with the base32 secret as {secret}; redirects keep their path and whether they carry a code; credentials keep their type and credentialData.')


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        raise SystemExit(f'reference OTP policy check failed: {error}') from None
