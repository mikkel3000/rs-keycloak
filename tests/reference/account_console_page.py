#!/usr/bin/env python3
"""Capture how pinned Keycloak serves the account console page and assets."""
import json
import pathlib
import re
import secrets

import oauth
from tokens import send


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True}, admin, expected=201)
    observations = {}
    clean = lambda value: value.replace(base, '{base}').replace(realm, '{realm}') if isinstance(value, str) else value
    try:
        status, headers, body = send(base + f'/realms/{realm}/account/')
        page = body.decode()
        environment = json.loads(re.search(r'<script id="environment" type="application/json">(.*?)</script>', page, re.S).group(1))
        resource_url = environment['resourceUrl']
        version = resource_url.split('/resources/', 1)[1].split('/', 1)[0]
        observations['page'] = {
            'status': status,
            'content_type': headers.get('Content-Type'),
            'environment': {key: clean(value).replace(version, '{version}') if isinstance(value, str) else value for key, value in environment.items()},
            'imports': sorted(clean(url).replace(version, '{version}') for url in re.findall(r'"react[^"]*": "([^"]+)"', page)),
            'module_scripts': len(re.findall(r'<script type="module" src="', page)),
            'stylesheets': len(re.findall(r'<link rel="stylesheet"', page)),
            'cache_control': headers.get('Cache-Control'),
            'csp': headers.get('Content-Security-Policy'),
        }
        entry = re.search(r'<script type="module" src="([^"]+)"', page).group(1)
        status, headers, body = send(entry if entry.startswith('http') else base + entry)
        observations['entry-script'] = {'status': status, 'content_type': headers.get('Content-Type'), 'cache_control': headers.get('Cache-Control'), 'path': re.sub(r'-[A-Za-z0-9_-]{8}\.js$', '-{hash}.js', clean(entry).replace(version, '{version}'))}
        react = re.search(r'"react": "([^"]+)"', page).group(1)
        status, headers, _ = send(react if react.startswith('http') else base + react)
        observations['vendor-react'] = {'status': status, 'content_type': headers.get('Content-Type')}
        status, headers, body = send(base + f'/resources/{realm}/account/en')
        messages = json.loads(body) if status == 200 else None
        observations['messages'] = {'status': status, 'content_type': headers.get('Content-Type'), 'is_list': isinstance(messages, list), 'count_over_100': isinstance(messages, list) and len(messages) > 100, 'item_fields': sorted({field for item in messages for field in item}) if isinstance(messages, list) else None}
        status, headers, body = send(base + '/realms/missing-realm/account/')
        observations['page/unknown-realm'] = {'status': status}
        baseline = pathlib.Path(__file__).with_name('account-console-page-observations.json')
        assert record or baseline.exists(), 'reference account console page baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference account console page case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference account console page case changed: {label}: {observations[label]}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'The account console page: its environment block, import map, scripts and styles, the entry script and vendor React assets, and the message bundle endpoint; shapes only.', 'normalization': 'The base URL, realm name and resource version are replaced with placeholders; asset hashes are reduced to a placeholder.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)
