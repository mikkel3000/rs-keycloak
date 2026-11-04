#!/usr/bin/env python3
"""Capture pinned Keycloak token introspection/revocation via public HTTP only."""
import base64
import hashlib
import http.cookiejar
import json
import pathlib
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import oauth


def send(url, fields=None, basic=None, bearer=None, opener=None, extra_headers=None, method=None):
    headers = {}
    if basic:
        headers['Authorization'] = 'Basic ' + base64.b64encode(':'.join(basic).encode()).decode()
    if bearer:
        headers['Authorization'] = 'Bearer ' + bearer
    headers.update(extra_headers or {})
    data = urllib.parse.urlencode(fields).encode() if fields is not None else None
    if data is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    try:
        response = (opener or urllib.request.build_opener()).open(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read(2 * 1024 * 1024)


def summary(response):
    status, headers, body = response
    parsed = json.loads(body) if body and headers.get_content_type() == 'application/json' else {}
    # Never retain claims, token strings, cookie values, or token-bearing URLs.
    return {'status': status, 'content_type': headers.get('Content-Type'), 'www_authenticate': headers.get('WWW-Authenticate'), 'empty_body': not body, 'body_fields': sorted(parsed), 'cache_control': headers.get('Cache-Control'), 'pragma': headers.get('Pragma'), 'cors': {name: headers.get(name) for name in ['Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Headers', 'Vary']}, 'body': {key: parsed[key] for key in ['active', 'error', 'error_description'] if key in parsed}}


def login(issuer, client, secret, password, browser=None, exchange=True):
    if browser is None:
        policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https', 'wss'))
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), oauth.Redirects())
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    redirect = issuer.split('/realms/')[0] + '/callback'
    state = secrets.token_urlsafe(20)
    query = urllib.parse.urlencode({'client_id': client, 'redirect_uri': redirect, 'response_type': 'code', 'scope': 'openid profile', 'state': state, 'code_challenge': challenge, 'code_challenge_method': 'S256'})
    status, headers, body = send(issuer + '/protocol/openid-connect/auth?' + query, opener=browser)
    if status == 200:
        form = oauth.Form()
        form.feed(body.decode())
        assert form.action and form.action.startswith(issuer + '/login-actions/'), 'login form origin'
        status, headers, body = send(form.action, list((form.fields | {'username': 'reference-user', 'password': password, 'credentialId': ''}).items()), opener=browser)
    assert status == 302, 'login callback status'
    callback = urllib.parse.urlparse(headers['Location'])
    assert callback.scheme + '://' + callback.netloc + callback.path == redirect, 'callback origin'
    result = urllib.parse.parse_qs(callback.query)
    assert result['state'] == [state], 'callback state'
    fields = [('grant_type', 'authorization_code'), ('client_id', client), ('redirect_uri', redirect), ('code', result['code'][0]), ('code_verifier', verifier)]
    if secret:
        fields.append(('client_secret', secret))
    if not exchange:
        return fields, browser
    status, _, body = send(issuer + '/protocol/openid-connect/token', fields)
    assert status == 200, 'code token status'
    tokens = json.loads(body)
    oauth.verify_token(tokens['access_token'], issuer)
    return tokens, browser


def run(base, bootstrap_secret, record=False):
    _, body = oauth.request(base + '/realms/master/protocol/openid-connect/token', [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(40)
    credentials = {'public-owner': None, 'conf-owner': secrets.token_urlsafe(40), 'conf-other': secrets.token_urlsafe(40), 'short-owner': secrets.token_urlsafe(40), 'no-aud-owner': secrets.token_urlsafe(40)}
    clients = [{'clientId': client, 'publicClient': secret is None, 'secret': secret, 'standardFlowEnabled': True, 'redirectUris': [base + '/callback'], 'webOrigins': ['https://registered.example.invalid'], 'attributes': {'pkce.code.challenge.method': 'S256'}} for client, secret in credentials.items()]
    next(client for client in clients if client['clientId'] == 'short-owner')['attributes']['access.token.lifespan'] = '1'
    next(client for client in clients if client['clientId'] == 'public-owner')['protocolMappers'] = [{'name': 'reference-audience', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper', 'config': {'included.client.audience': 'conf-other', 'access.token.claim': 'true', 'id.token.claim': 'false'}}]
    for client in clients:
        if client['clientId'] in ['conf-owner', 'conf-other', 'short-owner']:
            client['protocolMappers'] = [{'name': 'reference-self-audience', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper', 'config': {'included.client.audience': client['clientId'], 'access.token.claim': 'true', 'id.token.claim': 'false'}}]
    fixture = {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': clients, 'users': [{'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}]}
    oauth.request(base + '/admin/realms', fixture, admin, expected=201)
    observations = {}
    try:
        issuer = base + '/realms/' + realm
        endpoint = issuer + '/protocol/openid-connect'
        tokens = {client: login(issuer, client, secret, password)[0] for client, secret in credentials.items()}

        def probe(label, route, caller=None, token=None, hint=None, wrong_secret=False, basic=False, extra=(), omit_secret=False):
            fields = []
            auth = None
            if caller:
                if basic:
                    auth = (caller, secrets.token_urlsafe(40) if wrong_secret else credentials[caller])
                else:
                    fields.append(('client_id', caller))
                    if credentials[caller] is not None and not omit_secret:
                        fields.append(('client_secret', secrets.token_urlsafe(40) if wrong_secret else credentials[caller]))
            if token is not None:
                fields.append(('token', token))
            if hint is not None:
                fields.append(('token_type_hint', hint))
            response = send(endpoint + '/' + route, fields + list(extra), basic=auth)
            observations[label] = summary(response)
            return response

        for caller in ['public-owner', 'conf-owner']:
            for kind in ['access_token', 'refresh_token', 'id_token']:
                probe(f'introspect/{caller}/{kind}', 'token/introspect', caller, tokens[caller][kind])
            probe(f'introspect/{caller}/unknown', 'token/introspect', caller, 'not-a-token')
            probe(f'introspect/{caller}/missing', 'token/introspect', caller)
            probe(f'introspect/{caller}/unsupported-hint', 'token/introspect', caller, tokens[caller]['access_token'], 'unsupported')
            probe(f'revoke/{caller}/unknown', 'revoke', caller, 'not-a-token')
            probe(f'revoke/{caller}/missing', 'revoke', caller)
            probe(f'revoke/{caller}/id-token', 'revoke', caller, tokens[caller]['id_token'])
        for route in ['token/introspect', 'revoke']:
            probe(route + '/no-client', route, token='not-a-token')
            probe(route + '/missing-secret', route, 'conf-owner', 'not-a-token', omit_secret=True)
            probe(route + '/valid-secret-basic', route, 'conf-owner', 'not-a-token', basic=True)
            observations[route + '/unknown-client'] = summary(send(endpoint + '/' + route, [('client_id', 'unknown-client'), ('client_secret', secrets.token_urlsafe(40)), ('token', 'not-a-token')]))
            probe(route + '/wrong-secret-post', route, 'conf-owner', 'not-a-token', wrong_secret=True)
            probe(route + '/wrong-secret-basic', route, 'conf-owner', 'not-a-token', wrong_secret=True, basic=True)
        for route in ['token/introspect', 'revoke']:
            probe(route + '/duplicate-token', route, 'conf-owner', 'not-a-token', extra=[('token', 'another-unknown-token')])
        for kind in ['access_token', 'refresh_token']:
            probe('introspect/ownership/' + kind, 'token/introspect', 'conf-other', tokens['conf-owner'][kind])
            probe('revoke/ownership/' + kind, 'revoke', 'conf-other', tokens['conf-owner'][kind])
        probe('introspect/default-token-owner-not-in-audience', 'token/introspect', 'no-aud-owner', tokens['no-aud-owner']['access_token'])
        probe('introspect/public-token-audience-client', 'token/introspect', 'conf-other', tokens['public-owner']['access_token'])
        probe('introspect/public-refresh-not-owner', 'token/introspect', 'conf-other', tokens['public-owner']['refresh_token'])
        probe('revoke/public-caller-not-owner', 'revoke', 'public-owner', tokens['conf-owner']['access_token'])
        probe('revoke/confidential-caller-public-token', 'revoke', 'conf-other', tokens['public-owner']['access_token'])
        probe('introspect/refresh-with-access-hint', 'token/introspect', 'conf-owner', tokens['conf-owner']['refresh_token'], 'access_token')

        def refresh(label, client, token):
            fields = [('grant_type', 'refresh_token'), ('client_id', client), ('refresh_token', token)]
            if credentials[client]:
                fields.append(('client_secret', credentials[client]))
            response = send(endpoint + '/token', fields)
            observations[label] = summary(response)
            if response[0] == 200:
                assert 'access_token' in json.loads(response[2]), 'refresh token issuance'

        for client in ['public-owner', 'conf-owner']:
            current, _ = login(issuer, client, credentials[client], password)
            before = probe(f'effects/{client}/access-before-revoke', 'token/introspect', 'conf-other' if client == 'public-owner' else 'conf-owner', current['access_token'])
            assert json.loads(before[2])['active'] is True, 'access token active before revocation'
            probe(f'effects/{client}/revoke-access', 'revoke', client, current['access_token'])
            probe(f'effects/{client}/access-after-access-revoke', 'token/introspect', 'conf-other' if client == 'public-owner' else 'conf-owner', current['access_token'])
            observations[f'effects/{client}/userinfo-after-access-revoke'] = summary(send(endpoint + '/userinfo', bearer=current['access_token']))
            refresh(f'effects/{client}/refresh-after-access-revoke', client, current['refresh_token'])
            probe(f'effects/{client}/refresh-after-access-revoke-introspect', 'token/introspect', 'conf-owner', current['refresh_token'])
            fresh, _ = login(issuer, client, credentials[client], password)
            probe(f'effects/{client}/revoke-refresh', 'revoke', client, fresh['refresh_token'])
            probe(f'effects/{client}/refresh-after-refresh-revoke', 'token/introspect', 'conf-owner', fresh['refresh_token'])
            probe(f'effects/{client}/access-after-refresh-revoke', 'token/introspect', 'conf-owner', fresh['access_token'])
            observations[f'effects/{client}/userinfo-after-refresh-revoke'] = summary(send(endpoint + '/userinfo', bearer=fresh['access_token']))
            refresh(f'effects/{client}/refresh-grant-after-refresh-revoke', client, fresh['refresh_token'])
            probe(f'effects/{client}/repeat-refresh-revoke', 'revoke', client, fresh['refresh_token'])
        expired, _ = login(issuer, 'short-owner', credentials['short-owner'], password)
        expiry = oauth.verify_token(expired['access_token'], issuer)['exp']
        assert expiry - time.time() < 5, 'short token fixture expiration'
        time.sleep(max(0, expiry - time.time() + 1))
        probe('expired/introspect-access', 'token/introspect', 'short-owner', expired['access_token'])
        probe('expired/revoke-access', 'revoke', 'short-owner', expired['access_token'])
        refresh('expired/refresh-grant', 'short-owner', expired['refresh_token'])
        shared, browser = login(issuer, 'conf-owner', credentials['conf-owner'], password)
        sibling, _ = login(issuer, 'conf-other', credentials['conf-other'], password, browser)
        shared_claims = oauth.verify_token(shared['access_token'], issuer)
        sibling_claims = oauth.verify_token(sibling['access_token'], issuer)
        assert shared_claims['sid'] == sibling_claims['sid'], 'shared SSO fixture'
        before = probe('shared-session/sibling-before-revoke', 'token/introspect', 'conf-other', sibling['access_token'])
        assert json.loads(before[2])['active'] is True, 'sibling access active before revoke'
        probe('shared-session/revoke-owner-refresh', 'revoke', 'conf-owner', shared['refresh_token'])
        probe('shared-session/sibling-access', 'token/introspect', 'conf-other', sibling['access_token'])
        probe('shared-session/sibling-refresh', 'token/introspect', 'conf-other', sibling['refresh_token'])
        observations['shared-session/sibling-userinfo'] = summary(send(endpoint + '/userinfo', bearer=sibling['access_token']))
        refresh('shared-session/sibling-refresh-grant', 'conf-other', sibling['refresh_token'])
        for origin_label, origin in [('registered', 'https://registered.example.invalid'), ('unregistered', 'https://unregistered.example.invalid')]:
            for route in ['token', 'userinfo', 'certs']:
                observations[f'cors/{origin_label}/{route}/preflight'] = summary(send(endpoint + '/' + route, extra_headers={'Origin': origin, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'authorization,content-type'}, method='OPTIONS'))
            observations[f'cors/{origin_label}/certs/get'] = summary(send(endpoint + '/certs', extra_headers={'Origin': origin}))
            discovery_url = issuer + '/.well-known/openid-configuration'
            observations[f'cors/{origin_label}/discovery/get'] = summary(send(discovery_url, extra_headers={'Origin': origin}))
            observations[f'cors/{origin_label}/discovery/preflight'] = summary(send(discovery_url, extra_headers={'Origin': origin, 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization'}, method='OPTIONS'))
            observations[f'cors/{origin_label}/userinfo/get'] = summary(send(endpoint + '/userinfo', bearer=tokens['conf-owner']['access_token'], extra_headers={'Origin': origin}))
        code_fields, _ = login(issuer, 'public-owner', None, password, exchange=False)
        unauthorized = send(endpoint + '/token', code_fields, extra_headers={'Origin': 'https://unregistered.example.invalid'})
        observations['cors/unregistered/token/code-exchange'] = summary(unauthorized)
        observations['cors/registered/token/same-code-after-unregistered'] = summary(send(endpoint + '/token', code_fields, extra_headers={'Origin': 'https://registered.example.invalid'}))
        for observation in observations.values():
            if observation['www_authenticate']:
                observation['www_authenticate'] = observation['www_authenticate'].replace(realm, '{realm}')
        baseline = pathlib.Path(__file__).with_name('token-observations.json')
        assert record or baseline.exists(), 'reference token baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference token case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference token case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Selected token activation/error/header/session-effect and CORS checks; token and claim values are not snapshot parity evidence.', 'normalization': 'Only the random fixture realm in WWW-Authenticate is replaced with {realm}.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference token check failed: {detail}') from None
