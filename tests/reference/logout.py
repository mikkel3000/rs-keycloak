#!/usr/bin/env python3
"""Capture pinned Keycloak OIDC logout behavior via public HTTP only."""
import json
import pathlib
import secrets
import urllib.error
import urllib.parse
import urllib.request

import oauth
from tokens import login, send, summary


class NoRedirects(urllib.request.HTTPRedirectHandler):
    """Keeps the logout redirect itself as the observed response."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_without_redirects(url):
    try:
        response = urllib.request.build_opener(NoRedirects()).open(url, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read(2 * 1024 * 1024)


def logout_summary(response, base, realm):
    status, headers, body = response
    result = summary(response)
    location = headers.get('Location')
    if location:
        parsed = urllib.parse.urlsplit(location)
        result['location'] = (parsed.scheme + '://' + parsed.netloc + parsed.path).replace(base, '{base}').replace(realm, '{realm}')
        result['location_params'] = sorted(urllib.parse.parse_qs(parsed.query))
    result['html'] = (headers.get('Content-Type') or '').startswith('text/html')
    return result


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(40)
    callback = base + '/callback'
    client = {'clientId': 'logout-app', 'publicClient': True, 'standardFlowEnabled': True, 'redirectUris': [callback], 'attributes': {'pkce.code.challenge.method': 'S256', 'post.logout.redirect.uris': callback + '/logged-out'}}
    other = {'clientId': 'other-app', 'publicClient': True, 'standardFlowEnabled': True, 'redirectUris': [callback], 'attributes': {'pkce.code.challenge.method': 'S256'}}
    user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [client, other], 'users': [user]}, admin, expected=201)
    observations = {}
    issuer = base + '/realms/' + realm
    endpoint = issuer + '/protocol/openid-connect'

    def post(label, fields):
        observations[label] = logout_summary(send(endpoint + '/logout', fields), base, realm)

    def get(label, params):
        response = get_without_redirects(endpoint + '/logout?' + urllib.parse.urlencode(params))
        observations[label] = logout_summary(response, base, realm)
        return response

    def after(label, tokens, client_id='logout-app'):
        observations[label + '/refresh'] = summary(send(endpoint + '/token', [('grant_type', 'refresh_token'), ('client_id', client_id), ('refresh_token', tokens['refresh_token'])]))
        observations[label + '/userinfo'] = summary(send(endpoint + '/userinfo', bearer=tokens['access_token']))

    try:
        tokens, _ = login(issuer, 'logout-app', None, password)
        post('post/missing-refresh-token', [('client_id', 'logout-app')])
        post('post/no-client', [('refresh_token', tokens['refresh_token'])])
        post('post/other-client', [('client_id', 'other-app'), ('refresh_token', tokens['refresh_token'])])
        post('post/success', [('client_id', 'logout-app'), ('refresh_token', tokens['refresh_token'])])
        after('post/after', tokens)
        post('post/repeat', [('client_id', 'logout-app'), ('refresh_token', tokens['refresh_token'])])
        tokens, _ = login(issuer, 'logout-app', None, password)
        get('get/unregistered-redirect', {'id_token_hint': tokens['id_token'], 'post_logout_redirect_uri': callback + '/elsewhere'})
        get('get/no-hint', {'post_logout_redirect_uri': callback + '/logged-out', 'client_id': 'logout-app'})
        get('get/invalid-hint', {'id_token_hint': 'not-a-token', 'post_logout_redirect_uri': callback + '/logged-out'})
        get('get/redirect', {'id_token_hint': tokens['id_token'], 'post_logout_redirect_uri': callback + '/logged-out', 'state': 'logout-state'})
        after('get/after', tokens)
        tokens, _ = login(issuer, 'logout-app', None, password)
        get('get/hint-without-redirect', {'id_token_hint': tokens['id_token']})
        after('get/without-redirect-after', tokens)
        for observation in observations.values():
            if observation.get('www_authenticate'):
                observation['www_authenticate'] = observation['www_authenticate'].replace(realm, '{realm}')
        baseline = pathlib.Path(__file__).with_name('logout-observations.json')
        assert record or baseline.exists(), 'reference logout baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference logout case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference logout case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Refresh-token POST logout and RP-initiated GET logout with and without id_token_hint and registered post-logout redirect; status, headers, redirect shape and token effects only.', 'normalization': 'The random realm name and base URL are replaced with {realm} and {base}; redirect query values are reduced to parameter names.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference logout check failed: {detail}') from None
