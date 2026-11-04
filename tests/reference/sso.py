#!/usr/bin/env python3
"""Capture pinned Keycloak SSO cookie and prompt behavior via public HTTP only."""
import base64
import hashlib
import http.cookiejar
import json
import pathlib
import secrets
import time
import urllib.parse
import urllib.request

import oauth
from tokens import login, send


def cookie_summary(headers, realm):
    cookies = []
    for value in headers.get_all('Set-Cookie') or []:
        name, _, rest = value.partition('=')
        # Keycloak's per-login cookies vary between runs; only the SSO
        # session cookies are part of the observed contract.
        if name not in ('KEYCLOAK_IDENTITY', 'KEYCLOAK_SESSION'):
            continue
        attributes = sorted({part.strip().split('=', 1)[0].lower() for part in rest.split(';')[1:] if part.strip()})
        path = next((part.strip()[5:] for part in rest.split(';') if part.strip().lower().startswith('path=')), None)
        max_age = next((part.strip()[8:] for part in rest.split(';') if part.strip().lower().startswith('max-age=')), None)
        cookies.append({'name': name, 'path': path.replace(realm, '{realm}') if path else None, 'attributes': attributes, 'cleared': max_age == '0'})
    return sorted(cookies, key=lambda cookie: (cookie['name'], cookie['path'] or ''))


def authorize(browser, issuer, client, redirect, **extra):
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    query = urllib.parse.urlencode(dict({'client_id': client, 'redirect_uri': redirect, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': challenge, 'code_challenge_method': 'S256'}, **extra))
    status, headers, body = send(issuer + '/protocol/openid-connect/auth?' + query, opener=browser)
    result = {'status': status, 'cookies': cookie_summary(headers, issuer.rsplit('/', 1)[1])}
    if status in (302, 303):
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(headers['Location']).query)
        result['location_params'] = sorted(params)
        result['error'] = params.get('error', [None])[0]
    else:
        result['login_form'] = b'<form' in body
    return result


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(40)
    callback = base + '/callback'
    clients = [{'clientId': name, 'publicClient': True, 'standardFlowEnabled': True, 'redirectUris': [callback], 'attributes': {'pkce.code.challenge.method': 'S256', 'post.logout.redirect.uris': '+'}} for name in ('sso-app', 'sso-other')]
    user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': clients, 'users': [user]}, admin, expected=201)
    observations = {}
    issuer = base + '/realms/' + realm
    try:
        observations['prompt-none/no-session'] = authorize(urllib.request.build_opener(oauth.Redirects()), issuer, 'sso-app', callback, prompt='none')
        policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https', 'wss'))
        jar = http.cookiejar.CookieJar(policy=policy)
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), oauth.Redirects())
        fields, _ = login(issuer, 'sso-app', None, password, browser=browser, exchange=False)
        observations['login/cookie-names'] = sorted({cookie.name for cookie in jar} & {'KEYCLOAK_IDENTITY', 'KEYCLOAK_SESSION'})
        status, _, body = send(issuer + '/protocol/openid-connect/token', fields)
        first = json.loads(body)
        observations['sso/same-client'] = authorize(browser, issuer, 'sso-app', callback)
        observations['sso/other-client'] = authorize(browser, issuer, 'sso-other', callback)
        observations['prompt-none/with-session'] = authorize(browser, issuer, 'sso-app', callback, prompt='none')
        observations['prompt-login/with-session'] = authorize(browser, issuer, 'sso-app', callback, prompt='login')
        # max_age compares whole seconds of auth_time, so wait past the login second.
        time.sleep(1.1)
        observations['max-age-zero/with-session'] = authorize(browser, issuer, 'sso-app', callback, max_age='0')
        logout_query = urllib.parse.urlencode({'id_token_hint': first['id_token'], 'post_logout_redirect_uri': callback})
        status, headers, _ = send(issuer + '/protocol/openid-connect/logout?' + logout_query, opener=browser)
        observations['logout/cookies'] = {'status': status, 'cookies': cookie_summary(headers, realm)}
        observations['sso/after-logout'] = authorize(browser, issuer, 'sso-app', callback)
        baseline = pathlib.Path(__file__).with_name('sso-observations.json')
        assert record or baseline.exists(), 'reference SSO baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference SSO case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference SSO case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'SSO cookies after login, silent authorization for the same and another client, prompt=none, prompt=login, max_age=0, and cookie clearing at logout; SSO session cookie names, paths and attributes only.', 'normalization': 'The random realm name in cookie paths is replaced with {realm}; cookie values and codes are not retained.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference SSO check failed: {detail}') from None
