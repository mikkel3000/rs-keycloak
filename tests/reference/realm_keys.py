#!/usr/bin/env python3
"""Capture pinned Keycloak admin realm keys metadata."""
import json
import pathlib
import secrets

import oauth
from admin_realms import send_raw


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True}, admin, expected=201)
    auth = {'Authorization': 'Bearer ' + admin}
    observations = {}
    try:
        status, headers, body = send_raw(base + f'/admin/realms/{realm}/keys', 'GET', None, auth)
        parsed = json.loads(body)
        certs = json.loads(oauth.request(base + f'/realms/{realm}/protocol/openid-connect/certs')[1])
        jwks = {key['kid']: key for key in certs['keys']}
        observations['keys'] = {
            'status': status,
            'content_type': headers.get('Content-Type'),
            'fields': sorted(parsed),
            'active': {algorithm: kid in jwks for algorithm, kid in sorted(parsed['active'].items())},
            'key_fields': sorted({field for key in parsed['keys'] for field in key}),
            'keys': sorted([key['algorithm'], key['type'], key['use'], key['status'], key.get('providerPriority'), 'publicKey' in key, 'certificate' in key, key['kid'] in jwks] for key in parsed['keys']),
        }
        rs256 = next(key for key in parsed['keys'] if key['algorithm'] == 'RS256')
        observations['rs256/matches-jwks'] = {'modulus_in_jwks': jwks[rs256['kid']]['kty'] == 'RSA', 'public_key_base64': rs256['publicKey'][:4]}
        status, _, body = send_raw(base + '/admin/realms/missing-realm/keys', 'GET', None, auth)
        observations['keys/unknown-realm'] = {'status': status, 'body': json.loads(body)}
        status, _, body = send_raw(base + f'/admin/realms/{realm}/keys', 'GET', None, {})
        observations['keys/no-token'] = {'status': status, 'body': json.loads(body)}
        baseline = pathlib.Path(__file__).with_name('realm-key-observations.json')
        assert record or baseline.exists(), 'reference realm key baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations == expected, 'reference realm key cases changed'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Admin realm keys metadata for a new realm: active key per algorithm, key fields and their link to the JWKS, and errors; no key material is kept.', 'normalization': 'Key identifiers and material are reduced to presence and JWKS membership.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference realm key check failed: {detail}') from None
