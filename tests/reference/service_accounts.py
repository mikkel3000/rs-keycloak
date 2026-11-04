#!/usr/bin/env python3
"""Capture pinned Keycloak client-credentials grant behavior via public HTTP only."""
import json
import pathlib
import secrets

import oauth
from tokens import send, summary


def grant_summary(response):
    """Summary plus token field and claim names; never token or claim values."""
    result = summary(response)
    status, _, body = response
    if status != 200:
        return result
    tokens = json.loads(body)
    result['response_fields'] = sorted(tokens)
    result['token_type'] = tokens.get('token_type')
    result['scope'] = tokens.get('scope')
    result['refresh_expires_in'] = tokens.get('refresh_expires_in')
    claims = json.loads(oauth.unbase64(tokens['access_token'].split('.')[1]))
    result['access_claims'] = sorted(claims)
    result['access_typ'] = claims.get('typ')
    result['access_preferred_username'] = claims.get('preferred_username')
    result['access_aud'] = claims.get('aud')
    if 'id_token' in tokens:
        result['id_claims'] = sorted(json.loads(oauth.unbase64(tokens['id_token'].split('.')[1])))
    return result


def run(base, bootstrap_secret, record=False):
    _, body = oauth.request(base + '/realms/master/protocol/openid-connect/token', [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    secret, plain_secret = secrets.token_urlsafe(40), secrets.token_urlsafe(40)
    clients = [
        {'clientId': 'service-owner', 'publicClient': False, 'secret': secret, 'serviceAccountsEnabled': True, 'standardFlowEnabled': False, 'webOrigins': ['https://registered.example.invalid']},
        {'clientId': 'service-disabled', 'publicClient': False, 'secret': plain_secret, 'serviceAccountsEnabled': False, 'standardFlowEnabled': True, 'redirectUris': [base + '/callback']},
        {'clientId': 'service-public', 'publicClient': True, 'standardFlowEnabled': True, 'redirectUris': [base + '/callback']},
    ]
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': clients}, admin, expected=201)
    observations = {}
    try:
        issuer = base + '/realms/' + realm
        endpoint = issuer + '/protocol/openid-connect'

        def grant(label, fields, basic=None, headers=None):
            response = send(endpoint + '/token', [('grant_type', 'client_credentials')] + fields, basic=basic, extra_headers=headers)
            observations[label] = grant_summary(response)
            return json.loads(response[2]) if response[0] == 200 else None

        owner = [('client_id', 'service-owner'), ('client_secret', secret)]
        tokens = grant('grant/post-secret', owner)
        assert tokens, 'client credentials grant'
        oauth.verify_token(tokens['access_token'], issuer)
        grant('grant/basic-secret', [], basic=('service-owner', secret))
        grant('grant/openid-scope', owner + [('scope', 'openid')])
        grant('grant/unknown-scope', owner + [('scope', 'unknown-scope')])
        grant('grant/wrong-secret', [('client_id', 'service-owner'), ('client_secret', secrets.token_urlsafe(40))])
        grant('grant/service-accounts-disabled', [('client_id', 'service-disabled'), ('client_secret', plain_secret)])
        grant('grant/public-client', [('client_id', 'service-public')])
        grant('grant/no-client', [])
        grant('grant/registered-origin', owner, headers={'Origin': 'https://registered.example.invalid'})
        grant('grant/unregistered-origin', owner, headers={'Origin': 'https://unregistered.example.invalid'})
        access = tokens['access_token']
        observations['effects/userinfo'] = summary(send(endpoint + '/userinfo', bearer=access))
        openid = json.loads(send(endpoint + '/token', [('grant_type', 'client_credentials'), ('scope', 'openid')] + owner)[2])
        observations['effects/userinfo-openid'] = summary(send(endpoint + '/userinfo', bearer=openid['access_token']))
        introspect = lambda token: summary(send(endpoint + '/token/introspect', owner + [('token', token)]))
        observations['effects/introspect-before-revoke'] = introspect(access)
        observations['effects/revoke-access'] = summary(send(endpoint + '/revoke', owner + [('token', access)]))
        observations['effects/introspect-after-revoke'] = introspect(access)
        observations['effects/userinfo-openid-before-revoke'] = summary(send(endpoint + '/userinfo', bearer=openid['access_token']))
        observations['effects/revoke-openid-access'] = summary(send(endpoint + '/revoke', owner + [('token', openid['access_token'])]))
        observations['effects/userinfo-after-revoke'] = summary(send(endpoint + '/userinfo', bearer=openid['access_token']))
        observations['effects/grant-after-revoke'] = grant_summary(send(endpoint + '/token', [('grant_type', 'client_credentials')] + owner))
        for observation in observations.values():
            if observation['www_authenticate']:
                observation['www_authenticate'] = observation['www_authenticate'].replace(realm, '{realm}')
        baseline = pathlib.Path(__file__).with_name('service-account-observations.json')
        assert record or baseline.exists(), 'reference service account baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference service account case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference service account case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Client-credentials grant errors, response fields, claim names, and token effects; token and claim values are not retained except fixed type, scope and username.', 'normalization': 'Only the random fixture realm in WWW-Authenticate is replaced with {realm}.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference service account check failed: {detail}') from None
