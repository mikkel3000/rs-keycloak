#!/usr/bin/env python3
"""Capture pinned Keycloak's public realm endpoint, GET /realms/{realm}."""
import json
import pathlib
import secrets
import urllib.error
import urllib.request

import oauth


def fetch(url, method='GET', headers=None):
    request = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, dict(response.headers), response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read().decode()


def observe(base, realm, admin):
    status, headers, body = fetch(base + f'/realms/{realm}', headers={'Origin': 'https://other.example.test'})
    parsed = json.loads(body)
    certs = json.loads(oauth.request(base + f'/realms/{realm}/protocol/openid-connect/certs')[1])
    rsa = [key['n'] for key in certs['keys'] if key['kty'] == 'RSA' and key.get('use') == 'sig']
    return {
        'status': status,
        'content_type': headers.get('Content-Type'),
        'cache_control': headers.get('Cache-Control'),
        'allow_origin': headers.get('Access-Control-Allow-Origin'),
        'fields': sorted(parsed),
        'realm': parsed['realm'] == realm,
        'token_service': parsed['token-service'] == base + f'/realms/{realm}/protocol/openid-connect',
        'account_service': parsed['account-service'] == base + f'/realms/{realm}/account',
        'tokens_not_before': parsed['tokens-not-before'],
        'public_key_is_pem_body': parsed['public_key'].startswith('MII') and '\n' not in parsed['public_key'],
        'rsa_signing_keys': len(rsa),
    }


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True}, admin, expected=201)
    observations = {}
    try:
        observations['master'] = observe(base, 'master', admin)
        observations['new-realm'] = observe(base, realm, admin)
        status, headers, body = fetch(base + '/realms/missing-realm')
        observations['unknown-realm'] = {'status': status, 'content_type': headers.get('Content-Type'), 'body': json.loads(body)}
        oauth.request(base + '/admin/realms/' + realm, {'enabled': False}, admin, method='PUT', expected=204)
        status, headers, body = fetch(base + f'/realms/{realm}')
        observations['disabled-realm'] = {'status': status, 'content_type': headers.get('Content-Type'), 'fields': sorted(json.loads(body))}
        baseline = pathlib.Path(__file__).with_name('realm-info-observations.json')
        assert record or baseline.exists(), 'reference realm info baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations == expected, 'reference realm info cases changed'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Public realm endpoint GET /realms/{realm}: fields, URLs, headers, and errors for unknown and disabled realms.', 'normalization': 'URLs are compared with the base URL; the public key is reduced to its form.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference realm info check failed: {detail}') from None
