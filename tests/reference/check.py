#!/usr/bin/env python3
"""Public HTTP smoke checks; no credentials or private database writes."""
import argparse
import json
import urllib.error
import urllib.parse
import urllib.request


def get(base, path):
    request = urllib.request.Request(base.rstrip('/') + path, headers={'Accept': 'application/json'})
    try:
        response = urllib.request.urlopen(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(1024 * 1024)
        return response.status, response.headers.get_content_type(), json.loads(body)


def check(base):
    status, media, discovery = get(base, '/realms/master/.well-known/openid-configuration')
    assert status == 200 and media == 'application/json', 'discovery response'
    issuer = base.rstrip('/') + '/realms/master'
    assert discovery['issuer'] == issuer, 'issuer must match public origin'
    required = ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'end_session_endpoint']
    for name in required:
        assert discovery[name].startswith(issuer + '/'), name
    status, media, keys = get(base, '/realms/master/protocol/openid-connect/certs')
    assert status == 200 and media == 'application/json', 'JWKS response'
    assert keys['keys'] and all(key.get('kid') and key.get('kty') for key in keys['keys']), 'public keys'
    assert all('d' not in key and 'p' not in key for key in keys['keys']), 'private key leak'
    status, media, missing = get(base, '/realms/rs-keycloak-does-not-exist/.well-known/openid-configuration')
    assert status == 404 and media == 'application/json', 'unknown realm response'
    assert missing.get('error'), 'unknown realm error'
    return {'discovery_fields': sorted(discovery), 'grant_types_supported': sorted(discovery.get('grant_types_supported', [])), 'response_types_supported': sorted(discovery.get('response_types_supported', [])), 'unknown_realm': missing}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', required=True)
    parser.add_argument('--target')
    args = parser.parse_args()
    reference = check(args.reference)
    if args.target:
        target = check(args.target)
        assert reference == target, 'public smoke metadata differs'
    print(json.dumps({'public_smoke': 'passed', 'paired': bool(args.target), 'scope': 'discovery, public JWKS shape, unknown realm only'}))


if __name__ == '__main__':
    main()
