"""A login browser for recorders and contracts: a cookie jar that follows
redirects inside login-actions, fills forms and reads TOTP codes.

`call(method, path, headers, body)` sends one request and returns status,
header pairs and body, so the same browser drives the reference and this
server.
"""
import base64
import hashlib
import hmac
import html.parser
import json
import secrets
import struct
import time
import urllib.parse

from page_texts import page_texts


class Forms(html.parser.HTMLParser):
    """Collects each form's id, action and input names with their values;
    a checkbox counts only when checked."""

    def __init__(self):
        super().__init__()
        self.forms = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.forms.append({'id': attrs.get('id'), 'action': attrs.get('action'), 'fields': {}, 'checkboxes': {}})
        elif tag == 'input' and self.forms and attrs.get('name'):
            if attrs.get('type') == 'checkbox':
                self.forms[-1]['checkboxes'][attrs['name']] = 'checked' in attrs
            else:
                self.forms[-1]['fields'][attrs['name']] = attrs.get('value') or ''


def forms(data):
    reader = Forms()
    reader.feed(data.decode(errors='replace'))
    return reader.forms


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def base32(data):
    return base64.b32encode(data).decode().rstrip('=')


DIGESTS = {'HmacSHA1': hashlib.sha1, 'HmacSHA256': hashlib.sha256, 'HmacSHA512': hashlib.sha512}


def hotp(secret, counter, digits=6, algorithm='HmacSHA1'):
    """RFC 4226 over the secret string's bytes, as Keycloak's HmacOTP."""
    digest = hmac.new(secret.encode(), struct.pack('>Q', counter), DIGESTS[algorithm]).digest()
    offset = digest[-1] & 0x0f
    value = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff
    return str(value % 10 ** digits).zfill(digits)


def totp(secret, steps=0, digits=6, period=30, algorithm='HmacSHA1'):
    """RFC 6238: the code `steps` periods from now."""
    return hotp(secret, int(time.time() // period) + steps, digits, algorithm)


class Browser:
    """One browser on one realm."""

    def __init__(self, call, base, realm, callback, client='login-app'):
        self.call, self.base, self.realm, self.callback, self.client = call, base, realm, callback, client
        self.cookies = {}
        self.set_cookies = []

    def send(self, path, headers=None, method='GET', body=None):
        """Sends a request and follows redirects that stay in login-actions;
        keeps every Set-Cookie header seen on the way."""
        self.set_cookies = []
        while True:
            sent = dict(headers or {})
            if self.cookies:
                sent['Cookie'] = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
            status, pairs, data = self.call(method, path, sent, body)
            for header, value in pairs:
                if header.lower() == 'set-cookie':
                    self.set_cookies.append(value)
                    cookie, _, rest = value.partition('=')
                    content = rest.split(';', 1)[0]
                    if content and 'max-age=0' not in value.lower():
                        self.cookies[cookie] = content
                    else:
                        self.cookies.pop(cookie, None)
            found = {k.lower(): v for k, v in pairs}
            target = urllib.parse.urlsplit(urllib.parse.urljoin(self.base + '/', found.get('location', '')))
            if status not in (302, 303) or '/login-actions/' not in target.path:
                return status, found, data
            path, method, body = target.path + ('?' + target.query if target.query else ''), 'GET', None
            headers = {}

    def visit(self, href):
        parts = urllib.parse.urlsplit(urllib.parse.urljoin(self.base + '/', href.replace('&amp;', '&')))
        return self.send(parts.path + ('?' + parts.query if parts.query else ''))

    def authorize(self, query=None):
        self.verifier = secrets.token_urlsafe(48)
        params = {'client_id': self.client, 'redirect_uri': self.callback, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': b64(hashlib.sha256(self.verifier.encode()).digest()), 'code_challenge_method': 'S256'} | (query or {})
        return self.send(f'/realms/{self.realm}/protocol/openid-connect/auth?' + urllib.parse.urlencode(params))

    def exchange(self, response):
        """Trades the code of a redirect for tokens; returns the token
        response's JSON."""
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(response[1]['location']).query)['code'][0]
        form = urllib.parse.urlencode({'grant_type': 'authorization_code', 'client_id': self.client, 'code': code, 'redirect_uri': self.callback, 'code_verifier': self.verifier})
        status, _, data = self.call('POST', f'/realms/{self.realm}/protocol/openid-connect/token', {'Content-Type': 'application/x-www-form-urlencoded'}, form)
        assert status == 200, f'code exchange {status}: {data[:200]}'
        return json.loads(data)

    def submit(self, response, fields, form_id=None, checked=()):
        """Posts a page's form (the first, or the one with `form_id`) with
        its fields, `fields` over them, and the named checkboxes on."""
        found = forms(response[2])
        form = next(form for form in found if form_id in (None, form['id']))
        action = urllib.parse.urlsplit(urllib.parse.urljoin(self.base + '/', form['action'].replace('&amp;', '&')))
        target = action.path + ('?' + action.query if action.query else '')
        values = form['fields'] | {name: 'on' for name in checked} | fields
        values = {name: value for name, value in values.items() if value is not None}
        return self.send(target, {'Content-Type': 'application/x-www-form-urlencoded'}, 'POST', urllib.parse.urlencode(values))

    def sign_in(self, username, password, query=None, checked=()):
        return self.submit(self.authorize(query), {'username': username, 'password': password}, checked=checked)

    def shown(self, response):
        """A redirect's path and whether it carries a code, or the page's
        status, texts without the language choice, and form ids."""
        status, headers, data = response
        if status in (302, 303):
            target = urllib.parse.urlsplit(headers.get('location', ''))
            path = target.path.removeprefix(urllib.parse.urlsplit(self.base).path)
            return {'status': status, 'location': path, 'code': 'code' in urllib.parse.parse_qs(target.query)}
        texts = page_texts(data)
        return {'status': status, 'forms': [form['id'] for form in forms(data)]} | {key: value for key, value in texts.items() if key != 'languages' and value not in (None, [], {})}
