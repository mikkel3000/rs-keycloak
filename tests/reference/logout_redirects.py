#!/usr/bin/env python3
"""Capture pinned Keycloak post-logout redirect matching with wildcards."""
import json
import pathlib
import secrets
import urllib.parse

import oauth
from logout import get_without_redirects, logout_summary
from tokens import login


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(40)
    callback = base + '/callback'
    plus = {'clientId': 'plus-app', 'publicClient': True, 'redirectUris': [callback, base + '/app/*'], 'attributes': {'pkce.code.challenge.method': 'S256', 'post.logout.redirect.uris': '+'}}
    explicit = {'clientId': 'explicit-app', 'publicClient': True, 'redirectUris': [callback], 'attributes': {'pkce.code.challenge.method': 'S256', 'post.logout.redirect.uris': base + '/out/*'}}
    user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [plus, explicit], 'users': [user]}, admin, expected=201)
    observations = {}
    issuer = base + '/realms/' + realm

    def logout(label, client, redirect):
        tokens, _ = login(issuer, client, None, password)
        params = {'id_token_hint': tokens['id_token'], 'post_logout_redirect_uri': redirect, 'state': 'state'}
        observations[label] = logout_summary(get_without_redirects(issuer + '/protocol/openid-connect/logout?' + urllib.parse.urlencode(params)), base, realm)

    try:
        logout('plus/exact-redirect', 'plus-app', callback)
        logout('plus/wildcard-redirect', 'plus-app', base + '/app/out')
        logout('plus/outside', 'plus-app', base + '/elsewhere')
        logout('explicit/wildcard', 'explicit-app', base + '/out/done?x=1')
        logout('explicit/redirect-uri', 'explicit-app', callback)
        logout('explicit/dot-segment', 'explicit-app', base + '/out/../elsewhere')
        baseline = pathlib.Path(__file__).with_name('logout-redirect-observations.json')
        assert record or baseline.exists(), 'reference logout redirect baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations == expected, 'reference logout redirect cases changed'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'RP-initiated logout redirects for a client whose post-logout URIs follow its redirect URIs (+) and one with an explicit wildcard; status, redirect target and page kind only.', 'normalization': 'The random realm name and base URL are replaced with placeholders.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference logout redirect check failed: {detail}') from None
