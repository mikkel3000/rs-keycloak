#!/usr/bin/env python3
"""Capture pinned Keycloak's realm localization texts.

Covers the admin /localization endpoints (list locales, read a locale or one
text, set one text as text/plain, merge texts from JSON or an uploaded JSON
file, delete one text or a locale, the deprecated default-locale fallback,
and their refusals), texts given at realm creation and in a partial export,
and how realm texts override the login theme's messages on the login page,
an authorization error page and the logout confirmation: a realm text wins
over the theme's text of the same locale, but a theme text of a more
specific locale wins over a realm text of a less specific one; texts are
message patterns, and ${key} in them and in the realm's display name is
replaced by the key's message.
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

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from page_texts import page_texts  # noqa: E402

# Realm texts of the pages realm: de-CH pages read de-CH, de, the default
# fr, then en.
PAGE_TEXTS = {
    'en': {
        'loginAccountTitle': 'Realm sign in',
        'doLogIn': 'Realm go',
        'loginTitle': 'Enter {0} now',
        'password': "The user's secret",
        'realmName': 'Realm Name EN',
        'clientNotFoundMessage': 'Realm: no such client',
        'logoutConfirmHeader': 'Realm: really leave?',
        'quoted': 'Says ${realmName}',
    },
    'de': {
        'loginAccountTitle': 'Realm Anmeldung',
        'realmName': 'Realm Name DE',
        'clientNotFoundMessage': 'Realm: kein Client',
        'logoutConfirmHeader': 'Realm: wirklich gehen?',
    },
    'de-CH': {'doLogIn': 'Realm los'},
    'fr': {'usernameOrEmail': 'Identifiant du realm', 'rememberMe': 'Realm: se souvenir'},
}
SUPPORTED = ['en', 'de', 'de-CH', 'fr']


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def run(base, bootstrap_secret, record=False):
    location = urllib.parse.urlsplit(base)
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    prefix = 'reference-' + secrets.token_hex(6)
    names = {key: f'{prefix}-{key}' for key in ('api', 'created', 'pages', 'plain')}
    plain_client, plain_secret = 'plain-' + secrets.token_hex(4), secrets.token_urlsafe(40)
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

    def summary(response):
        status, pairs, data = response
        headers = dict((k.lower(), v) for k, v in pairs)
        kind = headers.get('content-type', '').split(';')[0].strip() or None
        result = {'status': status, 'content_type': kind}
        if data and kind == 'application/json':
            result['body'] = json.loads(data)
        elif data:
            result['text'] = data.decode()
        return result

    def localization(label, realm_key, path='', method='GET', token=None, body=None, content_type=None):
        headers = {} if token is False else {'Authorization': 'Bearer ' + (token or admin)}
        if content_type:
            headers['Content-Type'] = content_type
        response = call(f'/admin/realms/{names[realm_key]}/localization' + path, headers, method, body)
        observations[label] = summary(response)
        return response

    def multipart(parts):
        boundary = 'reference' + secrets.token_hex(8)
        chunks = []
        for name, filename, content in parts:
            disposition = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename else '')
            chunks.append(f'--{boundary}\r\nContent-Disposition: {disposition}\r\nContent-Type: application/json\r\n\r\n'.encode() + content + b'\r\n')
        return b''.join(chunks) + f'--{boundary}--\r\n'.encode(), 'multipart/form-data; boundary=' + boundary

    class Browser:
        """One browser: a cookie jar and a fixed Accept-Language."""

        def __init__(self, realm_key, language=None):
            self.realm, self.language, self.cookies = names[realm_key], language, {}

        def send(self, path):
            sent = {'Accept-Language': self.language} if self.language else {}
            jar = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
            if jar:
                sent['Cookie'] = jar
            status, pairs, data = call(path, sent)
            for header, value in pairs:
                if header.lower() == 'set-cookie':
                    cookie, _, rest = value.partition('=')
                    content = rest.split(';', 1)[0]
                    if content and 'max-age=0' not in value.lower():
                        self.cookies[cookie] = content
            return status, dict((k.lower(), v) for k, v in pairs), data

        def authorize(self, query=None, client='login-app'):
            verifier = secrets.token_urlsafe(48)
            params = {'client_id': client, 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': b64(hashlib.sha256(verifier.encode()).digest()), 'code_challenge_method': 'S256'}
            return self.send(f'/realms/{self.realm}/protocol/openid-connect/auth?' + urllib.parse.urlencode(params | (query or {})))

        def logout(self):
            return self.send(f'/realms/{self.realm}/protocol/openid-connect/logout')

    def shown(response):
        """The page's status, lang and texts."""
        status, _, data = response
        result = {'status': status}
        tag = re.search(r'<html[^>]*>', data.decode())
        lang = tag and re.search(r'\blang="([^"]*)"', tag.group(0))
        texts = page_texts(data)
        return result | {'lang': lang and lang.group(1)} | {key: value for key, value in texts.items() if key != 'languages' and value not in (None, [], {})}

    oauth.request(base + '/admin/realms/master/clients', {'clientId': plain_client, 'publicClient': False, 'secret': plain_secret, 'serviceAccountsEnabled': True, 'standardFlowEnabled': False}, admin, expected=201)
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', plain_client), ('client_secret', plain_secret)])
    unprivileged = json.loads(body)['access_token']
    clients = [{'clientId': 'login-app', 'publicClient': True, 'redirectUris': [callback]}]
    oauth.request(base + '/admin/realms', {'realm': names['api'], 'enabled': True, 'defaultLocale': 'en'}, admin, expected=201)
    oauth.request(base + '/admin/realms', {'realm': names['created'], 'enabled': True, 'localizationTexts': {'en': {'key-a': 'text-a_en', 'key-b': 'text-b_en'}, 'de': {'key-a': 'text-a_de'}}}, admin, expected=201)
    oauth.request(base + '/admin/realms', {'realm': names['pages'], 'enabled': True, 'sslRequired': 'none', 'displayName': '${realmName}', 'clients': clients, 'internationalizationEnabled': True, 'supportedLocales': SUPPORTED, 'defaultLocale': 'fr', 'rememberMe': True, 'localizationTexts': PAGE_TEXTS}, admin, expected=201)
    oauth.request(base + '/admin/realms', {'realm': names['plain'], 'enabled': True, 'sslRequired': 'none', 'displayName': 'Plain ${realmName}', 'clients': clients, 'localizationTexts': {'en': {'realmName': 'from texts', 'doLogIn': 'Plain go'}, 'de': {'doLogIn': 'Nicht gezeigt'}}}, admin, expected=201)
    try:
        # The admin endpoints.
        localization('locales/new', 'api')
        localization('locale/missing', 'api', '/en')
        localization('text/missing', 'api', '/en/key-a')
        localization('put/text', 'api', '/en/key-a', 'PUT', body=b'Text A', content_type='text/plain')
        localization('put/json-type', 'api', '/en/key-j', 'PUT', body=b'"Text J"', content_type='application/json')
        localization('put/empty', 'api', '/en/key-e', 'PUT', body=b'', content_type='text/plain')
        localization('text/after-put', 'api', '/en/key-a')
        localization('text/empty', 'api', '/en/key-e')
        localization('put/replace', 'api', '/en/key-a', 'PUT', body=b'Text A2 \xc3\xa4', content_type='text/plain')
        localization('text/after-replace', 'api', '/en/key-a')
        localization('post/merge', 'api', '/en', 'POST', body=json.dumps({'key-b': 'Text B', 'key-c': 'Text C'}).encode(), content_type='application/json')
        localization('locale/after-merge', 'api', '/en')
        localization('post/new-locale', 'api', '/de', 'POST', body=json.dumps({'key-a': 'Text A de'}).encode(), content_type='application/json')
        localization('post/empty-map', 'api', '/pt-BR', 'POST', body=b'{}', content_type='application/json')
        localization('post/malformed', 'api', '/de', 'POST', body=b'{', content_type='application/json')
        localization('post/not-strings', 'api', '/de', 'POST', body=b'{"key-n": 1}', content_type='application/json')
        localization('locales/after-posts', 'api')
        localization('locale/fallback', 'api', '/de?useRealmDefaultLocaleFallback=true')
        localization('locale/no-fallback', 'api', '/de?useRealmDefaultLocaleFallback=false')
        localization('locale/unknown', 'api', '/zz')
        data, kind = multipart([('file', 'texts.json', json.dumps({'key-f': 'Text F', 'key-g': 'Text G'}).encode())])
        localization('upload/file', 'api', '/fr', 'POST', body=data, content_type=kind)
        localization('locale/after-upload', 'api', '/fr')
        data, kind = multipart([('other', 'texts.json', b'{"key-x": "X"}')])
        localization('upload/no-file', 'api', '/fr', 'POST', body=data, content_type=kind)
        data, kind = multipart([('file', 'texts.json', b'not json')])
        localization('upload/malformed', 'api', '/fr', 'POST', body=data, content_type=kind)
        localization('delete/text', 'api', '/en/key-b', 'DELETE')
        localization('delete/text-repeat', 'api', '/en/key-b', 'DELETE')
        localization('delete/text-unknown-locale', 'api', '/zz/key-b', 'DELETE')
        localization('delete/last-text', 'api', '/de/key-a', 'DELETE')
        localization('locales/after-last-text', 'api')
        localization('locale/after-last-text', 'api', '/de')
        localization('delete/locale', 'api', '/de', 'DELETE')
        localization('delete/locale-repeat', 'api', '/de', 'DELETE')
        localization('locales/after-delete', 'api')
        localization('refused/no-token/locales', 'api', token=False)
        localization('refused/no-token/put', 'api', '/en/key-z', 'PUT', token=False, body=b'Z', content_type='text/plain')
        localization('refused/unprivileged/locales', 'api', token=unprivileged)
        localization('refused/unprivileged/locale', 'api', '/en', token=unprivileged)
        localization('refused/unprivileged/text', 'api', '/en/key-a', token=unprivileged)
        localization('refused/unprivileged/put', 'api', '/en/key-z', 'PUT', token=unprivileged, body=b'Z', content_type='text/plain')
        localization('refused/unprivileged/post', 'api', '/en', 'POST', token=unprivileged, body=b'{"key-z": "Z"}', content_type='application/json')
        localization('refused/unprivileged/delete', 'api', '/en', 'DELETE', token=unprivileged)
        status, _, data = call(f'/admin/realms/{names["api"]}/localization/en/key-a', {'Authorization': 'Bearer ' + admin})
        observations['text/unchanged-after-refusals'] = {'status': status, 'text': data.decode()}

        # Texts given at realm creation, the realm representation and a
        # partial export.
        localization('created/locales', 'created')
        localization('created/en', 'created', '/en')
        status, _, data = call(f'/admin/realms/{names["created"]}', {'Authorization': 'Bearer ' + admin})
        observations['created/representation'] = {'status': status, 'has_localization_texts': 'localizationTexts' in json.loads(data)}
        status, _, data = call(f'/admin/realms/{names["created"]}', {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}, 'PUT', json.dumps({'localizationTexts': {'en': {'key-p': 'from update'}}}).encode())
        observations['created/update-with-texts'] = {'status': status}
        localization('created/en-after-update', 'created', '/en')
        status, _, data = call(f'/admin/realms/{names["created"]}/partial-export', {'Authorization': 'Bearer ' + admin}, 'POST')
        observations['created/partial-export'] = {'status': status, 'localizationTexts': json.loads(data).get('localizationTexts')}
        status, _, data = call(f'/admin/realms/{names["api"]}/partial-export', {'Authorization': 'Bearer ' + admin}, 'POST')
        observations['api/partial-export'] = {'status': status, 'localizationTexts': json.loads(data).get('localizationTexts')}

        # Realm texts on the pages.
        for language in ('en', 'de', 'de-CH', 'fr'):
            observations[f'login/{language}'] = shown(Browser('pages', language).authorize())
        observations['login/ui-de-CH'] = shown(Browser('pages').authorize({'ui_locales': 'de-CH'}))
        for language in ('en', 'de'):
            observations[f'authorize-error/{language}'] = shown(Browser('pages', language).authorize(client='missing-app'))
            observations[f'logout-confirm/{language}'] = shown(Browser('pages', language).logout())
        observations['login/plain/de'] = shown(Browser('plain', 'de').authorize())
        observations['authorize-error/plain/de'] = shown(Browser('plain', 'de').authorize(client='missing-app'))

        # A text changed later shows on the next page.
        status, _, _ = call(f'/admin/realms/{names["pages"]}/localization/en/loginAccountTitle', {'Authorization': 'Bearer ' + admin, 'Content-Type': 'text/plain'}, 'PUT', b'Changed realm sign in')
        assert status == 204, f'text change {status}'
        call(f'/admin/realms/{names["pages"]}/localization/de-CH', {'Authorization': 'Bearer ' + admin}, 'DELETE')
        observations['login/en-after-change'] = shown(Browser('pages', 'en').authorize())
        observations['login/de-CH-after-delete'] = shown(Browser('pages', 'de-CH').authorize())
    finally:
        for name in names.values():
            oauth.request(base + '/admin/realms/' + name, token=admin, method='DELETE', expected=204)
        _, found = oauth.request(base + '/admin/realms/master/clients?clientId=' + plain_client, token=admin)
        for client in json.loads(found):
            oauth.request(base + '/admin/realms/master/clients/' + client['id'], token=admin, method='DELETE', expected=204)

    observations = json.loads(json.dumps(observations).replace(base, '{base}'))
    for key in sorted(names, key=lambda item: -len(names[item])):
        observations = json.loads(json.dumps(observations).replace(names[key], '{realm-' + key + '}'))
    baseline = pathlib.Path(__file__).with_name('realm-localization-observations.json')
    assert record or baseline.exists(), 'reference realm localization baseline missing'
    if not record:
        expected = json.loads(baseline.read_text())['observations']
        assert observations.keys() == expected.keys(), 'reference realm localization case inventory changed'
        for label in observations:
            assert observations[label] == expected[label], f'reference realm localization case changed: {label}: {observations[label]}'
    lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
    return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'The admin localization endpoints and their refusals, texts given at realm creation and in partial exports, and realm texts overriding the login theme on the login page, an authorization error page and the logout confirmation, with ${key} resolved in texts and the display name.', 'normalization': 'The base URL and realm names are replaced with placeholders; admin responses keep status, media type and body; pages are reduced by tests/page_texts.py to title, heading, labels, buttons, links, messages and field errors, without the language choice.', 'paired_texts': PAGE_TEXTS, 'observations': observations}


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        raise SystemExit(f'reference realm localization check failed: {error}') from None
