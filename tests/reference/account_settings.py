#!/usr/bin/env python3
"""Capture how pinned Keycloak's realm and client settings reach the account console.

Covers client name and description in the admin API, the console's referrer
and the applications list; realm internationalization (enabled flag,
supported and default locales) in the admin API, the page locale and text
direction, and /account/supportedLocales; and editUsernameAllowed and
registrationEmailAsUsername in the admin API, the page features and the
account profile rules.
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

FLAG_FIELDS = ('internationalizationEnabled', 'supportedLocales', 'defaultLocale', 'editUsernameAllowed', 'registrationEmailAsUsername')
MANY_LOCALES = ['en', 'de', 'fr', 'ar', 'pt-BR', 'zh-CN', 'ja', 'fa', 'he']


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def run(base, bootstrap_secret, record=False):
    location = urllib.parse.urlsplit(base)
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    prefix, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    names = {key: f'{prefix}-{key}' for key in ('plain', 'i18n', 'pair', 'off', 'edit', 'email', 'both', 'update')}
    callback = base + '/callback'
    clients = [
        {'clientId': 'named-app', 'name': 'Named App', 'description': 'Shows a name', 'publicClient': True, 'redirectUris': [callback], 'baseUrl': callback},
        {'clientId': 'plain-app', 'publicClient': True, 'redirectUris': [callback], 'baseUrl': callback},
    ]
    settings = {
        'plain': {'clients': clients},
        'i18n': {'internationalizationEnabled': True, 'supportedLocales': MANY_LOCALES, 'defaultLocale': 'de'},
        'pair': {'internationalizationEnabled': True, 'supportedLocales': ['en', 'de']},
        'off': {'internationalizationEnabled': False, 'supportedLocales': ['en', 'de'], 'defaultLocale': 'de'},
        'edit': {'editUsernameAllowed': True},
        'email': {'registrationEmailAsUsername': True},
        'both': {'editUsernameAllowed': True, 'registrationEmailAsUsername': True},
        'update': {},
    }
    for key, extra in settings.items():
        oauth.request(base + '/admin/realms', {'realm': names[key], 'enabled': True, 'sslRequired': 'none'} | extra, admin, expected=201)
    for key in ('plain', 'i18n', 'pair', 'off', 'edit', 'email', 'both'):
        for username, email in (('reference-user', 'reference@example.invalid'), ('other-user', 'other@example.invalid')):
            oauth.request(base + f'/admin/realms/{names[key]}/users', {'username': username, 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': email, 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}, admin, expected=201)
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

    def realm_fields(label, key):
        _, realm = admin_call('/' + names[key])
        observations[label] = {field: realm.get(field, '<absent>') for field in FLAG_FIELDS}

    def update(label, key, payload):
        status, body = admin_call('/' + names[key], 'PUT', payload)
        observations[label] = {'status': status, 'body': body}

    def client_fields(key, client_id):
        _, found = admin_call(f'/{names[key]}/clients?clientId={client_id}')
        return {field: found[0].get(field, '<absent>') for field in ('name', 'description')}, found[0]['id']

    def environment(page):
        match = re.search(r'<script id="environment" type="application/json">(.*?)</script>', page, re.S)
        return json.loads(match.group(1))

    def page(label, key, headers=None, query=None):
        path = f'/realms/{names[key]}/account/' + ('?' + urllib.parse.urlencode(query) if query else '')
        status, pairs, body = call(path, headers)
        text = body.decode()
        env = environment(text)
        observations[label] = {'status': status, 'html': re.search(r'<html[^>]*>', text).group(0), 'locale': env['locale'], 'content_language': dict((k.lower(), v) for k, v in pairs).get('content-language'), 'referrerName': env['referrerName'], 'features': {name: env['features'][name] for name in ('isRegistrationEmailAsUsername', 'isEditUserNameAllowed', 'isInternationalizationEnabled')}, 'set_cookies': sorted(value.split('=', 1)[0] for k, value in pairs if k.lower() == 'set-cookie')}

    def login(key, client, redirect, username='reference-user', cookies=None, extra=None):
        """Signs in through the form, or by SSO with cookies; returns tokens and cookies."""
        name = names[key]
        cookies = dict(cookies or {})
        verifier = secrets.token_urlsafe(48)
        query = urllib.parse.urlencode({'client_id': client, 'redirect_uri': redirect, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': b64(hashlib.sha256(verifier.encode()).digest()), 'code_challenge_method': 'S256'} | (extra or {}))
        jar = lambda: '; '.join(f'{k}={v}' for k, v in cookies.items())
        status, pairs, body = call(f'/realms/{name}/protocol/openid-connect/auth?' + query, {'Cookie': jar()} if cookies else {})
        for header, value in pairs:
            if header.lower() == 'set-cookie':
                cookie, _, rest = value.partition('=')
                cookies[cookie] = rest.split(';', 1)[0]
        if status == 200:
            form = oauth.Form()
            form.feed(body.decode())
            action = urllib.parse.urlsplit(form.action)
            fields = urllib.parse.urlencode(form.fields | {'username': username, 'password': password, 'credentialId': ''})
            status, pairs, _ = call(action.path + '?' + action.query, {'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': jar()}, 'POST', fields)
            for header, value in pairs:
                if header.lower() == 'set-cookie':
                    cookie, _, rest = value.partition('=')
                    cookies[cookie] = rest.split(';', 1)[0]
        assert status == 302, f'login status {status} for {key}'
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(dict((k.lower(), v) for k, v in pairs)['location']).query)['code'][0]
        status, _, body = call(f'/realms/{name}/protocol/openid-connect/token', {'Content-Type': 'application/x-www-form-urlencoded'}, 'POST', urllib.parse.urlencode({'grant_type': 'authorization_code', 'client_id': client, 'redirect_uri': redirect, 'code': code, 'code_verifier': verifier}))
        return json.loads(body), {k: v for k, v in cookies.items() if v}

    def account(key, token, path='/', method='GET', payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        status, _, body = call(f'/realms/{names[key]}/account' + path, {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, method, data)
        return status, json.loads(body) if body else None

    def fresh_user(key, case):
        """Creates a user for one case and signs them in; returns their token and profile."""
        username, email = case + '-user', case + '@example.invalid'
        oauth.request(base + f'/admin/realms/{names[key]}/users', {'username': username, 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': email, 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}, admin, expected=201)
        tokens, _ = login(key, 'account-console', base + f'/realms/{names[key]}/account/', email)
        _, profile = account(key, tokens['access_token'], '/?userProfileMetadata=true')
        return tokens['access_token'], profile

    def profile_rules(label, key):
        _, profile = fresh_user(key, 'metadata')
        metadata = {item['name']: item if item['name'] in ('username', 'email') else {field: item.get(field) for field in ('required', 'readOnly')} for item in profile['userProfileMetadata']['attributes']}
        observations[label + '/metadata'] = {'username': profile.get('username'), 'email': profile.get('email'), 'attributes': metadata}
        cases = [
            ('rename', lambda own: {'username': 'renamed-user', 'email': own['email']}),
            ('taken-username', lambda own: {'username': 'other-user', 'email': own['email']}),
            ('new-email', lambda own: {'username': own['username'], 'email': 'changed@example.invalid'}),
            ('taken-email', lambda own: {'username': own['username'], 'email': 'other@example.invalid'}),
            ('no-username', lambda own: {'email': 'renamed@example.invalid'}),
        ]
        for case, payload in cases:
            # Each case has its own user, so no case sees another's changes.
            token, own = fresh_user(key, case)
            status, body = account(key, token, '/', 'POST', payload(own) | {'firstName': 'Reference', 'lastName': 'User'})
            _, after = account(key, token, '/')
            observations[f'{label}/{case}'] = {'before': [own['username'], own['email']], 'status': status, 'body': body, 'after': [after.get('username'), after.get('email')]}

    try:
        # Admin representation of the realm settings.
        for key in ('plain', 'i18n', 'pair', 'off', 'edit', 'email', 'both'):
            realm_fields('admin/realm/' + key, key)
        update('admin/update/enable-i18n', 'update', {'internationalizationEnabled': True, 'supportedLocales': ['fr', 'en'], 'defaultLocale': 'fr'})
        realm_fields('admin/update/after-enable-i18n', 'update')
        update('admin/update/locales-only', 'update', {'supportedLocales': ['en', 'de', 'ja']})
        realm_fields('admin/update/after-locales-only', 'update')
        update('admin/update/disable-i18n', 'update', {'internationalizationEnabled': False})
        realm_fields('admin/update/after-disable-i18n', 'update')
        update('admin/update/clear-default', 'update', {'defaultLocale': ''})
        realm_fields('admin/update/after-clear-default', 'update')
        update('admin/update/null-default', 'update', {'defaultLocale': None, 'supportedLocales': None})
        realm_fields('admin/update/after-null-default', 'update')
        update('admin/update/empty-locales', 'update', {'supportedLocales': []})
        realm_fields('admin/update/after-empty-locales', 'update')
        update('admin/update/locales-text', 'update', {'supportedLocales': 'de'})
        update('admin/update/i18n-text', 'update', {'internationalizationEnabled': 'yes'})
        update('admin/update/flags', 'update', {'editUsernameAllowed': True, 'registrationEmailAsUsername': True})
        realm_fields('admin/update/after-flags', 'update')
        update('admin/update/flag-text', 'update', {'editUsernameAllowed': 'yes'})

        # Client name and description.
        named, named_id = client_fields('plain', 'named-app')
        plain, plain_id = client_fields('plain', 'plain-app')
        observations['admin/client/named'] = named
        observations['admin/client/plain'] = plain
        observations['admin/client/built-in'] = {client: client_fields('plain', client)[0] for client in ('account', 'account-console', 'admin-cli', 'broker', 'realm-management', 'security-admin-console')}
        page('page/referrer-named', 'plain', query={'referrer': 'named-app'})
        page('page/referrer-plain', 'plain', query={'referrer': 'plain-app'})
        status, _ = admin_call(f'/{names["plain"]}/clients/{named_id}', 'PUT', {'name': 'Renamed App', 'description': 'Changed'})
        observations['admin/client/rename'] = {'status': status, 'after': client_fields('plain', 'named-app')[0]}
        page('page/referrer-renamed', 'plain', query={'referrer': 'named-app'})
        status, _ = admin_call(f'/{names["plain"]}/clients/{named_id}', 'PUT', {'name': '', 'description': ''})
        observations['admin/client/clear'] = {'status': status, 'after': client_fields('plain', 'named-app')[0]}
        page('page/referrer-cleared', 'plain', query={'referrer': 'named-app'})
        status, _ = admin_call(f'/{names["plain"]}/clients/{named_id}', 'PUT', {'name': None, 'description': None})
        observations['admin/client/null'] = {'status': status, 'after': client_fields('plain', 'named-app')[0]}
        status, _ = admin_call(f'/{names["plain"]}/clients/{named_id}', 'PUT', {'name': 'Named App', 'description': 'Shows a name'})
        observations['admin/client/restore'] = {'status': status, 'after': client_fields('plain', 'named-app')[0]}
        status, _ = admin_call(f'/{names["plain"]}/clients/{plain_id}', 'PUT', {'name': 7})
        observations['admin/client/number-name'] = {'status': status, 'after': client_fields('plain', 'plain-app')[0]}
        tokens, cookies = login('plain', 'account-console', base + f'/realms/{names["plain"]}/account/')
        login('plain', 'named-app', callback, cookies=cookies)
        login('plain', 'plain-app', callback, cookies=cookies)
        _, listed = account('plain', tokens['access_token'], '/applications')
        observations['account/applications'] = sorted([item['clientId'], item.get('clientName', '<absent>'), item.get('description', '<absent>')] for item in listed)

        # Internationalization: page locale, direction and supported locales.
        page('page/i18n/no-header', 'i18n')
        page('page/i18n/accept-de-de', 'i18n', {'Accept-Language': 'de-DE,de;q=0.9'})
        page('page/i18n/accept-fr', 'i18n', {'Accept-Language': 'fr'})
        page('page/i18n/accept-unsupported', 'i18n', {'Accept-Language': 'it, en;q=0.5'})
        page('page/i18n/accept-none-supported', 'i18n', {'Accept-Language': 'it'})
        page('page/i18n/accept-ar', 'i18n', {'Accept-Language': 'ar'})
        page('page/i18n/accept-fa', 'i18n', {'Accept-Language': 'fa-IR'})
        page('page/i18n/accept-he', 'i18n', {'Accept-Language': 'he'})
        page('page/i18n/accept-pt', 'i18n', {'Accept-Language': 'pt'})
        page('page/i18n/accept-pt-pt', 'i18n', {'Accept-Language': 'pt-PT'})
        page('page/i18n/accept-zh-tw', 'i18n', {'Accept-Language': 'zh-TW'})
        page('page/i18n/accept-zh', 'i18n', {'Accept-Language': 'zh'})
        page('page/i18n/accept-quality', 'i18n', {'Accept-Language': 'fr;q=0.2, ja;q=0.8'})
        page('page/i18n/accept-uppercase', 'i18n', {'Accept-Language': 'FR'})
        page('page/i18n/accept-wildcard', 'i18n', {'Accept-Language': '*'})
        page('page/i18n/cookie-fr', 'i18n', {'Cookie': 'KEYCLOAK_LOCALE=fr', 'Accept-Language': 'ja'})
        page('page/i18n/cookie-unsupported', 'i18n', {'Cookie': 'KEYCLOAK_LOCALE=it', 'Accept-Language': 'ja'})
        page('page/i18n/kc-locale', 'i18n', {'Accept-Language': 'ja'}, {'kc_locale': 'fr'})
        page('page/pair/no-header', 'pair')
        page('page/pair/accept-de', 'pair', {'Accept-Language': 'de'})
        page('page/pair/accept-fr', 'pair', {'Accept-Language': 'fr'})
        page('page/off/accept-de', 'off', {'Accept-Language': 'de'})
        page('page/plain/accept-de', 'plain', {'Accept-Language': 'de'})
        for key in ('i18n', 'pair', 'off', 'plain'):
            tokens, _ = login(key, 'account-console', base + f'/realms/{names[key]}/account/')
            status, listed = account(key, tokens['access_token'], '/supportedLocales')
            observations[f'account/supported-locales/{key}'] = {'status': status, 'body': listed}

        # The user's own locale: the console stores it as the locale attribute.
        tokens, cookies = login('i18n', 'account-console', base + f'/realms/{names["i18n"]}/account/', extra={'ui_locales': 'ja'})
        observations['login/i18n-ui-locales-cookies'] = sorted(cookies)
        token = tokens['access_token']
        _, profile = account('i18n', token, '/?userProfileMetadata=true')
        observations['account/i18n/profile'] = {'fields': sorted(profile), 'attributes': profile.get('attributes', '<absent>'), 'metadata_names': [item['name'] for item in profile['userProfileMetadata']['attributes']], 'locale_metadata': next(item for item in profile['userProfileMetadata']['attributes'] if item['name'] == 'locale')}
        identity = {'Cookie': '; '.join(f'{k}={v}' for k, v in cookies.items() if k in ('KEYCLOAK_IDENTITY', 'KEYCLOAK_SESSION'))}
        page('page/i18n/signed-in', 'i18n', identity | {'Accept-Language': 'fr'})
        update_body = {'username': 'reference-user', 'email': 'reference@example.invalid', 'firstName': 'Reference', 'lastName': 'User', 'attributes': {'locale': ['ar']}}
        status, body = account('i18n', token, '/', 'POST', update_body)
        _, profile = account('i18n', token, '/')
        observations['account/i18n/set-locale'] = {'status': status, 'body': body, 'attributes': profile.get('attributes', '<absent>')}
        page('page/i18n/signed-in-with-locale', 'i18n', identity | {'Accept-Language': 'fr'})
        status, body = account('i18n', token, '/', 'POST', update_body | {'attributes': {'locale': ['it']}})
        _, profile = account('i18n', token, '/')
        observations['account/i18n/set-unsupported-locale'] = {'status': status, 'body': body, 'attributes': profile.get('attributes', '<absent>')}
        page('page/i18n/signed-in-unsupported-locale', 'i18n', identity | {'Accept-Language': 'fr'})
        status, body = account('i18n', token, '/', 'POST', update_body | {'attributes': {}})
        _, profile = account('i18n', token, '/')
        observations['account/i18n/drop-locale'] = {'status': status, 'body': body, 'attributes': profile.get('attributes', '<absent>')}
        tokens, _ = login('plain', 'account-console', base + f'/realms/{names["plain"]}/account/')
        status, body = account('plain', tokens['access_token'], '/', 'POST', update_body)
        _, profile = account('plain', tokens['access_token'], '/')
        observations['account/plain/set-locale'] = {'status': status, 'body': body, 'attributes': profile.get('attributes', '<absent>')}

        # Username settings: page features and profile rules.
        for key in ('plain', 'edit', 'email', 'both'):
            page(f'page/flags/{key}', key)
        for key in ('edit', 'email', 'both'):
            _, users = admin_call(f'/{names[key]}/users?briefRepresentation=true')
            observations[f'admin/users/{key}'] = sorted([user['username'], user.get('email')] for user in users)
        for key in ('plain', 'edit', 'email', 'both'):
            profile_rules('profile/' + key, key)

        observations = json.loads(clean(json.dumps(observations)))
        baseline = pathlib.Path(__file__).with_name('account-settings-observations.json')
        assert record or baseline.exists(), 'reference account settings baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference account settings case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference account settings case changed: {label}: {observations[label]}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Client name and description; realm internationalizationEnabled, supportedLocales and defaultLocale; editUsernameAllowed and registrationEmailAsUsername; as the admin API stores them and as the account console page, applications list, supported locales and profile rules follow them.', 'normalization': 'The base URL and realm names are replaced with placeholders; only selected fields are kept.', 'observations': observations}
    finally:
        for name in names.values():
            oauth.request(base + '/admin/realms/' + name, token=admin, method='DELETE', expected=204)
