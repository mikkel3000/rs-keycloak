#!/usr/bin/env python3
"""Capture how pinned Keycloak serves the whole account console.

Covers the console page and its sub-paths, the environment for anonymous and
signed-in visitors, theme resources, message bundles, the two session
iframes keycloak-js loads, the KEYCLOAK_SESSION cookie those iframes read,
and the account API calls the console makes with its JSON content type.
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

# Headers that change per request or carry secrets.
SKIPPED = {'date', 'content-length', 'set-cookie', 'connection', 'keep-alive', 'transfer-encoding'}
ENTRY = 'assets/main-YR-28UU6.js'


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def run(base, bootstrap_secret, record=False):
    location = urllib.parse.urlsplit(base)
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    i18n, flags = realm + '-i18n', realm + '-flags'
    callback = base + '/callback'
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'groups': [{'name': 'staff', 'subGroups': [{'name': 'team'}]}], 'clients': [{'clientId': 'plain-app', 'name': 'Plain App', 'publicClient': True, 'redirectUris': [callback]}]}, admin, expected=201)
    oauth.request(base + '/admin/realms', {'realm': i18n, 'enabled': True, 'sslRequired': 'none', 'internationalizationEnabled': True, 'supportedLocales': ['en', 'de'], 'defaultLocale': 'en'}, admin, expected=201)
    oauth.request(base + '/admin/realms', {'realm': flags, 'enabled': True, 'sslRequired': 'none', 'editUsernameAllowed': True, 'registrationEmailAsUsername': True}, admin, expected=201)
    for name in (realm, i18n):
        oauth.request(base + f'/admin/realms/{name}/users', {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'groups': ['/staff/team'] if name == realm else [], 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}, admin, expected=201)
    observations = {}
    version = None

    def clean(value):
        value = value.replace(base, '{base}').replace(flags, '{realm}-flags').replace(i18n, '{realm}-i18n').replace(realm, '{realm}')
        return value.replace(version, '{version}') if version else value

    def call(path, headers=None, method='GET', body=None):
        connection = http.client.HTTPConnection(location.hostname, location.port, timeout=15)
        try:
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            pairs = response.getheaders()
            return response.status, pairs, response.read()
        finally:
            connection.close()

    def header_map(pairs):
        return {name.lower(): clean(value) for name, value in sorted(pairs) if name.lower() not in SKIPPED}

    def environment(page):
        match = re.search(r'<script id="environment" type="application/json">(.*?)</script>', page, re.S)
        return {key: clean(value) if isinstance(value, str) else value for key, value in json.loads(match.group(1)).items()} if match else None

    def login(name, client, redirect):
        """Signs in through the form; returns the token response and cookies."""
        verifier = secrets.token_urlsafe(48)
        query = urllib.parse.urlencode({'client_id': client, 'redirect_uri': redirect, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': b64(hashlib.sha256(verifier.encode()).digest()), 'code_challenge_method': 'S256'})
        status, pairs, body = call(f'/realms/{name}/protocol/openid-connect/auth?' + query)
        cookies = {value.split('=', 1)[0]: value.split(';', 1)[0].split('=', 1)[1] for key, value in pairs if key.lower() == 'set-cookie'}
        form = oauth.Form()
        form.feed(body.decode())
        action = urllib.parse.urlsplit(form.action)
        fields = urllib.parse.urlencode(form.fields | {'username': 'reference-user', 'password': password, 'credentialId': ''})
        status, pairs, _ = call(action.path + '?' + action.query, {'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': '; '.join(f'{k}={v}' for k, v in cookies.items())}, 'POST', fields)
        assert status == 302, f'login status {status}'
        for key, value in pairs:
            if key.lower() == 'set-cookie':
                cookie, _, rest = value.partition('=')
                cookies[cookie] = rest.split(';', 1)[0]
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(dict((k.lower(), v) for k, v in pairs)['location']).query)['code'][0]
        status, _, body = call(f'/realms/{name}/protocol/openid-connect/token', {'Content-Type': 'application/x-www-form-urlencoded'}, 'POST', urllib.parse.urlencode({'grant_type': 'authorization_code', 'client_id': client, 'redirect_uri': redirect, 'code': code, 'code_verifier': verifier}))
        return json.loads(body), {key: value for key, value in cookies.items() if value}

    def resource(label, path, headers=None):
        status, pairs, body = call(path, headers)
        observations[label] = {'status': status, 'headers': header_map(pairs), 'body_sha256': hashlib.sha256(body).hexdigest() if status == 200 else None}

    def messages(label, path, headers=None, method='GET'):
        status, pairs, body = call(path, headers, method)
        listed = json.loads(body) if status == 200 and body else None
        pairs_sorted = sorted([item['key'], item['value']] for item in listed) if isinstance(listed, list) else None
        observations[label] = {
            'status': status,
            'headers': header_map(pairs),
            'count': len(listed) if isinstance(listed, list) else None,
            'item_fields': sorted({field for item in listed for field in item}) if isinstance(listed, list) else None,
            'sources': sorted({item.get('source') for item in listed if 'source' in item}) if isinstance(listed, list) else None,
            'pairs_sha256': hashlib.sha256(json.dumps(pairs_sorted, ensure_ascii=False).encode()).hexdigest() if pairs_sorted is not None else None,
            'locale_names': {key: value for key, value in pairs_sorted if key.startswith('locale_')} if pairs_sorted is not None else None,
        }

    try:
        page_path = f'/realms/{realm}/account/'
        status, pairs, body = call(page_path)
        page = body.decode()
        resource_url = environment(page)['resourceUrl']
        version = resource_url.split('/resources/', 1)[1].split('/', 1)[0]
        observations['resource-version'] = {'length': len(version), 'value': version}
        root = clean(page)
        observations['page'] = {'status': status, 'headers': header_map(pairs), 'body': root}
        for label, path in [('page/sub-path', 'personal-info'), ('page/deep-sub-path', 'account-security/signing-in'), ('page/api-path-in-browser', 'applications'), ('page/query', '?tab=1')]:
            status, pairs, body = call(page_path + path)
            observations[label] = {'status': status, 'same_body': clean(body.decode()) == root, 'location': header_map(pairs).get('location')}
        for label, path in [('page/no-slash', f'/realms/{realm}/account'), ('page/index-html', f'/realms/{realm}/account/index.html'), ('page/unknown-realm', '/realms/missing-realm/account/')]:
            status, pairs, body = call(path)
            observations[label] = {'status': status, 'content_type': header_map(pairs).get('content-type'), 'location': header_map(pairs).get('location'), 'same_body': clean(body.decode(errors='replace')) == root, 'json_body': json.loads(body) if header_map(pairs).get('content-type') == 'application/json' else None}
        for label, query in [('page/referrer', {'referrer': 'plain-app', 'referrer_uri': callback}), ('page/referrer-foreign-uri', {'referrer': 'plain-app', 'referrer_uri': 'https://elsewhere.example.invalid/'}), ('page/referrer-unknown', {'referrer': 'missing-app'}), ('page/scope', {'scope': 'offline_access'})]:
            status, _, body = call(page_path + '?' + urllib.parse.urlencode(query))
            env = environment(body.decode())
            observations[label] = {'status': status, 'referrerName': env['referrerName'], 'referrerUrl': env['referrerUrl'], 'scope': env['scope']}
        account, cookies = login(realm, 'account-console', base + page_path)
        observations['cookie/session'] = {'names': sorted(cookies), 'hash_of_session_state': cookies.get('KEYCLOAK_SESSION') == b64(hashlib.sha384(account['session_state'].encode()).digest())}
        status, pairs, body = call(page_path, {'Cookie': '; '.join(f'{k}={v}' for k, v in cookies.items())})
        env = environment(body.decode())
        observations['page/signed-in'] = {'status': status, 'features': env['features'], 'locale': env['locale'], 'set_cookies': sorted(value.split('=', 1)[0] for key, value in pairs if key.lower() == 'set-cookie')}
        status, _, body = call(f'/realms/{i18n}/account/', {'Accept-Language': 'de-DE,de;q=0.9'})
        page = body.decode()
        observations['page/i18n-accept-language'] = {'status': status, 'locale': environment(page)['locale'], 'html': re.search(r'<html[^>]*>', page).group(0), 'features': environment(page)['features']}
        status, _, body = call(f'/realms/{i18n}/account/', {'Accept-Language': 'fr'})
        observations['page/i18n-unsupported-language'] = {'status': status, 'locale': environment(body.decode())['locale']}
        status, _, body = call(f'/realms/{flags}/account/')
        observations['page/realm-flags'] = {'status': status, 'features': environment(body.decode())['features']}

        theme = f'/resources/{version}/account/keycloak.v3/'
        common = f'/resources/{version}/common/keycloak/'
        resource('asset/entry', theme + ENTRY)
        resource('asset/stylesheet', theme + 'assets/main-BigPikZE.css')
        resource('asset/font', theme + 'assets/RedHatDisplayVF-CYDHf1NI.woff2')
        resource('asset/source-map', theme + ENTRY + '.map')
        resource('asset/favicon', theme + 'favicon.svg')
        resource('asset/content-json', theme + 'content.json')
        resource('asset/common-react', common + 'vendor/react/react.production.min.js')
        resource('asset/common-font', common + 'vendor/patternfly-v3/fonts/OpenSans-Regular-webfont.woff2')
        resource('asset/common-css', common + 'vendor/patternfly-v3/css/patternfly.min.css')
        etag = dict((k.lower(), v) for k, v in call(theme + ENTRY)[1]).get('etag')
        resource('asset/if-none-match', theme + ENTRY, {'If-None-Match': etag} if etag else {})
        resource('asset/other-version-hashed', f'/resources/abcde/account/keycloak.v3/{ENTRY}')
        resource('asset/other-version-plain', '/resources/abcde/account/keycloak.v3/favicon.svg')
        resource('asset/other-version-common', '/resources/abcde/common/keycloak/vendor/react/react.production.min.js')
        resource('asset/bad-version', '/resources/not-a-version!/account/keycloak.v3/favicon.svg')
        resource('asset/unknown-file', theme + 'assets/missing.js')
        resource('asset/unknown-theme', f'/resources/{version}/account/missing-theme/favicon.svg')
        resource('asset/unknown-type', f'/resources/{version}/nothing/keycloak.v3/favicon.svg')
        resource('asset/traversal', theme + '..%2f..%2fcommon/keycloak/vendor/react/react.production.min.js')
        resource('asset/directory', theme + 'assets/')
        resource('asset/template', theme + 'index.ftl')
        resource('asset/theme-properties', theme + 'theme.properties')
        resource('asset/messages-file', theme + 'messages/messages_en.properties')

        messages('messages/en', f'/resources/{realm}/account/en')
        messages('messages/de', f'/resources/{realm}/account/de')
        messages('messages/de-DE', f'/resources/{realm}/account/de-DE')
        messages('messages/zh-Hant', f'/resources/{realm}/account/zh-Hant')
        messages('messages/unknown-locale', f'/resources/{realm}/account/xx')
        messages('messages/i18n-de', f'/resources/{i18n}/account/de')
        messages('messages/i18n-fr', f'/resources/{i18n}/account/fr')
        messages('messages/source', f'/resources/{realm}/account/en?source=true')
        messages('messages/theme-param', f'/resources/{realm}/account/en?theme=keycloak.v3')
        tags = ['ar', 'az', 'ca', 'cs', 'da', 'de', 'el', 'en', 'es', 'eu', 'fa', 'fi', 'fr', 'hr', 'hu', 'hy', 'id', 'it', 'ja', 'ka', 'kk', 'ko', 'ky', 'lt', 'lv', 'nl', 'no', 'pl', 'pt', 'pt-BR', 'ro', 'ru', 'sk', 'sl', 'sv', 'th', 'tr', 'uk', 'vi', 'zh-CN', 'zh-TW', 'zh-Hans', 'zh-Hant']
        by_locale = {}
        for tag in tags:
            messages('messages/by-locale', f'/resources/{realm}/account/{tag}')
            item = observations.pop('messages/by-locale')
            by_locale[tag] = {'count': item['count'], 'pairs_sha256': item['pairs_sha256'], 'locale_names': item['locale_names']}
        observations['messages/by-locale'] = by_locale
        messages('messages/login-type', f'/resources/{realm}/login/en')
        messages('messages/unknown-type', f'/resources/{realm}/nothing/en')
        messages('messages/unknown-realm', '/resources/missing-realm/account/en')
        messages('messages/cors', f'/resources/{realm}/account/en', {'Origin': 'https://app.example.invalid'})
        messages('messages/preflight', f'/resources/{realm}/account/en', {'Origin': 'https://app.example.invalid', 'Access-Control-Request-Method': 'GET'}, 'OPTIONS')

        endpoints = f'/realms/{realm}/protocol/openid-connect/'
        resource('iframe/3p-step1', endpoints + '3p-cookies/step1.html')
        resource('iframe/3p-step2', endpoints + '3p-cookies/step2.html')
        resource('iframe/3p-version', endpoints + f'3p-cookies/step1.html?version={version}')
        resource('iframe/3p-other-version', endpoints + '3p-cookies/step1.html?version=abcde')
        resource('iframe/login-status', endpoints + 'login-status-iframe.html')
        resource('iframe/login-status-other-version', endpoints + 'login-status-iframe.html?version=abcde')
        resource('iframe/login-status-unknown-realm', '/realms/missing-realm/protocol/openid-connect/login-status-iframe.html')
        status, _, body = call(endpoints + 'login-status-iframe.html')
        observations['iframe/login-status']['body'] = clean(body.decode())
        for label, query in [('own-origin', {'client_id': 'account-console', 'origin': base}), ('foreign-origin', {'client_id': 'account-console', 'origin': 'https://elsewhere.example.invalid'}), ('unknown-client', {'client_id': 'missing-app', 'origin': base}), ('no-origin', {'client_id': 'account-console'}), ('no-client', {'origin': base})]:
            resource('iframe/init/' + label, endpoints + 'login-status-iframe.html/init?' + urllib.parse.urlencode(query))

        bearer = {'Authorization': 'Bearer ' + account['access_token']}
        console_headers = bearer | {'Content-Type': 'application/json'}

        def api(label, path, headers=console_headers):
            status, pairs, body = call(f'/realms/{realm}/account' + path, headers)
            parsed = json.loads(body) if body and dict((k.lower(), v) for k, v in pairs).get('content-type', '').startswith('application/json') else None
            observations[label] = {'status': status, 'content_type': header_map(pairs).get('content-type'), 'json': parsed is not None, 'is_page': body.startswith(b'<!doctype html>')}
            return parsed

        profile = api('api/profile-with-metadata', '/?userProfileMetadata=true')
        observations['api/profile-with-metadata'] |= {'fields': sorted(profile), 'metadata_fields': sorted(profile['userProfileMetadata']), 'metadata': profile['userProfileMetadata']}
        profile = api('api/profile-without-metadata', '/')
        observations['api/profile-without-metadata']['fields'] = sorted(profile)
        api('api/profile-accept-json', '/', bearer | {'Accept': 'application/json'})
        api('api/profile-no-json-headers', '/', bearer)
        api('api/credentials', '/credentials')
        api('api/credentials-no-json-headers', '/credentials', bearer)
        locales = api('api/supported-locales', '/supportedLocales')
        observations['api/supported-locales']['body'] = locales
        groups = api('api/groups', '/groups')
        observations['api/groups']['body'] = [{key: value for key, value in item.items() if key not in ('id', 'parentId')} | {'has_id': 'id' in item, 'has_parent_id': 'parentId' in item} for item in groups]
        groups = api('api/groups-brief', '/groups?briefRepresentation=false')
        observations['api/groups-brief']['fields'] = sorted({field for item in groups for field in item})
        linked = api('api/linked-accounts', '/linked-accounts')
        observations['api/linked-accounts']['body'] = linked
        api('api/no-token-json', '/credentials', {'Content-Type': 'application/json'})
        i18n_account, _ = login(i18n, 'account-console', base + f'/realms/{i18n}/account/')
        status, pairs, body = call(f'/realms/{i18n}/account/supportedLocales', {'Authorization': 'Bearer ' + i18n_account['access_token'], 'Content-Type': 'application/json'})
        observations['api/i18n-supported-locales'] = {'status': status, 'body': json.loads(body)}

        baseline = pathlib.Path(__file__).with_name('account-console-observations.json')
        assert record or baseline.exists(), 'reference account console baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference account console case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference account console case changed: {label}: {observations[label]}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'The account console page and sub-paths for anonymous and signed-in visitors, theme resources, message bundles, the session iframes, the KEYCLOAK_SESSION cookie and the account API calls the console makes; full page bodies and resource digests.', 'normalization': 'The base URL, realm names and resource version are replaced with placeholders, except in resource-version; message bundles are kept as a digest of their sorted pairs.', 'observations': observations}
    finally:
        for name in (realm, i18n, flags):
            oauth.request(base + '/admin/realms/' + name, token=admin, method='DELETE', expected=204)
