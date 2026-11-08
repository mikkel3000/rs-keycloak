#!/usr/bin/env python3
"""Capture pinned Keycloak's TOTP setup QR code and its manual mode.

Covers what the CONFIGURE_TOTP page's QR code holds (TotpUtils.qrCode,
QRCodeUtils and OTPPolicy.getKeyURI: a 246-pixel zxing code of the
otpauth URI, whose issuer is the realm's display name with ${key} resolved
in the user's locale, else the realm name, with ':' replaced), the
manual-entry mode its link opens (the key in groups of four and the
policy), the link back to the QR code, and which mode a failed code
re-shows.
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
import qr_code  # noqa: E402

REALMS = {
    'named': {'displayName': '${realmName}', 'internationalizationEnabled': True, 'supportedLocales': ['en', 'de'], 'defaultLocale': 'en', 'localizationTexts': {'en': {'realmName': 'Realm: Name EN'}, 'de': {'realmName': 'Realm Name DE'}}},
    'plain': {},
    'colon': {'displayName': 'A:B & C+D/é'},
}


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def base32(data):
    return base64.b32encode(data).decode().rstrip('=')


def run(base, bootstrap_secret, record=False):
    location = urllib.parse.urlsplit(base)
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    prefix, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    names = {key: f'{prefix}-{key}' for key in REALMS}
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
                found = dict((k.lower(), v) for k, v in pairs)
                target = urllib.parse.urlsplit(urllib.parse.urljoin(base, found.get('location', '')))
                if status not in (302, 303) or '/login-actions/' not in target.path:
                    return status, found, data
                path, method, body = target.path + ('?' + target.query if target.query else ''), 'GET', None
                headers = {}

        def visit(self, href):
            parts = urllib.parse.urlsplit(urllib.parse.urljoin(base, href.replace('&amp;', '&')))
            return self.send(parts.path + ('?' + parts.query if parts.query else ''))

        def sign_in(self, login, query=None):
            verifier = secrets.token_urlsafe(48)
            params = {'client_id': 'login-app', 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': b64(hashlib.sha256(verifier.encode()).digest()), 'code_challenge_method': 'S256'} | (query or {})
            page = self.send(f'/realms/{names[self.key]}/protocol/openid-connect/auth?' + urllib.parse.urlencode(params))
            return self.submit(page, {'username': login, 'password': password, 'credentialId': ''})

        def submit(self, response, fields):
            forms = Forms()
            forms.feed(response[2].decode())
            form = forms.forms[0]
            action = urllib.parse.urlsplit(urllib.parse.urljoin(base, form['action'].replace('&amp;', '&')))
            target = action.path + ('?' + action.query if action.query else '')
            return self.send(target, {'Content-Type': 'application/x-www-form-urlencoded'}, 'POST', urllib.parse.urlencode(form['fields'] | fields))

    def secret_of(response):
        forms = Forms()
        forms.feed(response[2].decode())
        return next(form for form in forms.forms if 'totpSecret' in form['fields'])['fields']

    def shown(response):
        """The page's texts, its QR code and its shown key, with the secret
        as a placeholder."""
        status, _, data = response
        text = data.decode()
        fields = secret_of(response)
        secret = fields['totpSecret']
        encoded = base32(secret.encode())
        grouped = ' '.join(encoded[i:i + 4] for i in range(0, len(encoded), 4))
        texts = json.loads(json.dumps(page_texts(data)).replace(grouped, '{key}'))
        # The reference lists the applications in hash order.
        texts['items'].sort()
        result = {'status': status, 'mode_field': fields.get('mode')} | {key: value for key, value in texts.items() if key != 'languages' and value not in (None, [], {})}
        image = re.search(r'<img[^>]*id="kc-totp-secret-qr-code"[^>]*src="data:image/png;base64,\s*([^"]+)"', text)
        if image:
            code = qr_code.read(base64.b64decode(image.group(1)))
            code['text'] = code['text'].replace(base32(secret.encode()), '{secret}')
            result['qr'] = code
        key = re.search(r'id="kc-totp-secret-key"[^>]*>([^<]*)<', text)
        if key:
            encoded = base32(secret.encode())
            grouped = ' '.join(encoded[i:i + 4] for i in range(0, len(encoded), 4))
            result['key'] = {'grouped': key.group(1).strip() == grouped, 'length': len(key.group(1).strip())}
        result['secret_length'] = len(secret)
        modes = {}
        for link_id in ('mode-manual', 'mode-barcode'):
            link = re.search(r'<a href="([^"]*)" id="' + link_id + '"', text)
            if link:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(link.group(1).replace('&amp;', '&')).query)
                modes[link_id] = {'path': urllib.parse.urlsplit(link.group(1)).path.rsplit('/', 1)[-1], 'mode': query.get('mode'), 'execution': query.get('execution')}
        result['mode_links'] = modes
        return result

    def new_user(key, username, extra=None):
        user = {'username': username, 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': secrets.token_hex(4) + '@example.invalid', 'emailVerified': True, 'requiredActions': ['CONFIGURE_TOTP'], 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]} | (extra or {})
        status, _, _ = call(f'/admin/realms/{names[key]}/users', {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}, 'POST', json.dumps(user).encode())
        assert status == 201, f'user creation {status}'
        return username

    clients = [{'clientId': 'login-app', 'publicClient': True, 'redirectUris': [callback]}]
    for key, extra in REALMS.items():
        oauth.request(base + '/admin/realms', {'realm': names[key], 'enabled': True, 'sslRequired': 'none', 'clients': clients} | extra, admin, expected=201)
    try:
        browser = Browser('named')
        page = browser.sign_in(new_user('named', 'qr-user'))
        observations['qr/named/en'] = shown(page)
        manual = browser.visit(re.search(r'<a href="([^"]*)" id="mode-manual"', page[2].decode()).group(1))
        observations['manual/named/en'] = shown(manual)
        observations['manual-failed/named/en'] = shown(browser.submit(manual, {'totp': '', 'userLabel': ''}))
        back = browser.visit(re.search(r'<a href="([^"]*)" id="mode-barcode"', manual[2].decode()).group(1))
        observations['qr-again/named/en'] = shown(back)
        observations['qr-again-failed/named/en'] = shown(browser.submit(back, {'totp': '', 'userLabel': ''}))
        observations['same-secret'] = len({secret_of(response)['totpSecret'] for response in (page, manual, back)}) == 1

        browser = Browser('named')
        observations['qr/named/user-de'] = shown(browser.sign_in(new_user('named', 'de-user', {'attributes': {'locale': ['de']}})))
        browser = Browser('named')
        observations['qr/named/ui-de'] = shown(browser.sign_in(new_user('named', 'ui-user'), {'ui_locales': 'de'}))
        browser = Browser('plain')
        observations['qr/plain'] = shown(browser.sign_in(new_user('plain', 'name+tag@example.invalid')))
        browser = Browser('colon')
        observations['qr/colon'] = shown(browser.sign_in(new_user('colon', 'colon-user')))
    finally:
        for name in names.values():
            oauth.request(base + '/admin/realms/' + name, token=admin, method='DELETE', expected=204)

    observations = json.loads(json.dumps(observations).replace(base, '{base}'))
    for key in sorted(names, key=lambda item: -len(names[item])):
        observations = json.loads(json.dumps(observations).replace(names[key], '{realm-' + key + '}'))
    baseline = pathlib.Path(__file__).with_name('totp-qr-observations.json')
    assert record or baseline.exists(), 'reference TOTP QR baseline missing'
    if not record:
        expected = json.loads(baseline.read_text())['observations']
        assert observations.keys() == expected.keys(), 'reference TOTP QR case inventory changed'
        for label in observations:
            assert observations[label] == expected[label], f'reference TOTP QR case changed: {label}: {observations[label]}'
    lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
    return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'The CONFIGURE_TOTP page: what its QR code holds and how it is drawn, the issuer from the display name with ${key} resolved in the user locale, the manual-entry mode and the links between the modes, and the mode a failed code re-shows.', 'normalization': 'The base URL and realm names are replaced with placeholders; the QR code is read by tests/qr_code.py into its pixel size, module size, quiet zone, version, error correction level, segment modes and text, with the base32 secret as {secret}; pages are reduced by tests/page_texts.py without the language choice; the shown key is reduced to whether it is the base32 secret in groups of four.', 'observations': observations}


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        raise SystemExit(f'reference TOTP QR check failed: {error}') from None
