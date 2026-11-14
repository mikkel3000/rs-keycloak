#!/usr/bin/env python3
"""Capture pinned Keycloak's client protocol mappers: mappers given at
client creation, as the upstream test framework's OAuth client carries an
audience mapper, the protocol-mappers admin API, and the audience mapper's
effect on tokens."""
import json
import urllib.parse

import oauth
from recording import Recording

AUDIENCE = {
    'name': 'audience-test-app',
    'protocol': 'openid-connect',
    'protocolMapper': 'oidc-audience-mapper',
    'config': {'included.custom.audience': 'test-app', 'access.token.claim': 'true'},
}


def audiences(claims):
    aud = claims.get('aud')
    return sorted(aud) if isinstance(aud, list) else aud


def mapper_summary(mapper):
    return {'fields': sorted(mapper), 'name': mapper.get('name'), 'protocol': mapper.get('protocol'), 'protocolMapper': mapper.get('protocolMapper'), 'consentRequired': mapper.get('consentRequired'), 'config': mapper.get('config')}


def run(base, bootstrap_secret, record=False):
    recording = Recording(base, bootstrap_secret, ['mappers'])
    observations = {}
    try:
        recording.create_realms({'mappers': {}})
        name = recording.names['mappers']
        secret = 'test-secret-' + recording.password[:12]

        def create_client(label, payload):
            status, headers, body = recording.call('POST', f'/admin/realms/{name}/clients', {'Authorization': 'Bearer ' + recording.admin, 'Content-Type': 'application/json'}, json.dumps(payload).encode())
            observations[f'create-client/{label}'] = {'status': status, 'body': json.loads(body) if body else None}
            location = dict((key.lower(), value) for key, value in headers).get('location')
            return location.rsplit('/', 1)[1] if location else None

        app = create_client('test-app', {'clientId': 'test-app', 'secret': secret, 'serviceAccountsEnabled': True, 'redirectUris': [recording.callback], 'protocolMappers': [AUDIENCE]})
        plain = create_client('no-mappers', {'clientId': 'plain-app'})
        create_client('duplicate-names', {'clientId': 'twice-app', 'protocolMappers': [AUDIENCE, AUDIENCE]})
        create_client('unnamed', {'clientId': 'unnamed-app', 'protocolMappers': [{key: value for key, value in AUDIENCE.items() if key != 'name'}]})
        public = create_client('public', {'clientId': 'id-app', 'publicClient': True, 'redirectUris': [recording.callback], 'protocolMappers': [{
            'name': 'audience-in-id-token', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper',
            'config': {'included.client.audience': 'test-app', 'id.token.claim': 'true', 'access.token.claim': 'true'},
        }]})
        _, client = recording.admin_call('mappers', f'/clients/{app}')
        observations['client/test-app'] = [mapper_summary(mapper) for mapper in client['protocolMappers']]
        _, client = recording.admin_call('mappers', f'/clients/{plain}')
        observations['client/no-mappers'] = {'has_field': 'protocolMappers' in client}
        models = f'/clients/{app}/protocol-mappers/models'
        status, listed = recording.admin_call('mappers', models)
        observations['models/list'] = {'status': status, 'mappers': [mapper_summary(mapper) for mapper in listed]}
        audience_id = listed[0]['id']
        status, one = recording.admin_call('mappers', f'{models}/{audience_id}')
        observations['models/one'] = {'status': status, 'mapper': mapper_summary(one), 'id_matches': one['id'] == audience_id}
        for protocol in ('openid-connect', 'saml'):
            status, listed = recording.admin_call('mappers', f'/clients/{app}/protocol-mappers/protocol/{protocol}')
            observations[f'models/protocol-{protocol}'] = {'status': status, 'names': [mapper['name'] for mapper in listed]}

        def post(label, payload):
            status, headers, body = recording.call('POST', f'/admin/realms/{name}/clients/{app}/protocol-mappers/models', {'Authorization': 'Bearer ' + recording.admin, 'Content-Type': 'application/json'}, json.dumps(payload).encode())
            location = dict((key.lower(), value) for key, value in headers).get('location')
            observations[f'post/{label}'] = {'status': status, 'body': json.loads(body) if body else None, 'location': location.replace(base, '{base}').replace(app, '{client}').rsplit('/', 1)[0] if location else None}
            return location.rsplit('/', 1)[1] if location else None

        second = post('client-audience', {'name': 'client-audience', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper', 'config': {'included.client.audience': 'plain-app'}})
        post('duplicate-name', dict(AUDIENCE))
        post('unknown-type', {'name': 'unknown', 'protocol': 'openid-connect', 'protocolMapper': 'no-such-mapper', 'config': {}})
        post('missing-name', {'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper', 'config': {}})
        post('missing-protocol', {'name': 'no-protocol', 'protocolMapper': 'oidc-audience-mapper', 'config': {}})
        _, created = recording.admin_call('mappers', f'{models}/{second}')
        observations['models/created'] = mapper_summary(created)

        def put(label, mapper_id, payload):
            status, body = recording.admin_call('mappers', f'{models}/{mapper_id}', 'PUT', payload)
            observations[f'put/{label}'] = {'status': status, 'body': body}

        put('rename-and-config', second, {'id': second, 'name': 'renamed', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper', 'config': {'included.custom.audience': 'other-audience', 'introspection.token.claim': 'false'}})
        _, updated = recording.admin_call('mappers', f'{models}/{second}')
        observations['models/updated'] = mapper_summary(updated)
        put('id-mismatch', second, {'id': 'other-id', 'name': 'renamed', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper', 'config': {}})
        put('unknown', 'no-such-mapper-id', {'name': 'x', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper', 'config': {}})
        status, body = recording.admin_call('mappers', f'{models}/{second}', 'DELETE')
        observations['delete'] = {'status': status, 'body': body}
        observations['delete/after'] = dict(zip(('status', 'body'), recording.admin_call('mappers', f'{models}/{second}')))
        observations['delete/again'] = dict(zip(('status', 'body'), recording.admin_call('mappers', f'{models}/{second}', 'DELETE')))
        status, body = recording.admin_call('mappers', f'/clients/{plain}/protocol-mappers/add-models', 'POST', [
            {'name': 'first', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper', 'config': {'included.custom.audience': 'one'}},
            {'name': 'second', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper', 'config': {'included.custom.audience': 'two'}},
        ])
        observations['add-models'] = {'status': status, 'body': body, 'names': sorted(mapper['name'] for mapper in recording.admin_call('mappers', f'/clients/{plain}/protocol-mappers/models')[1])}
        status, client = recording.admin_call('mappers', f'/clients/{plain}')
        status, _ = recording.admin_call('mappers', f'/clients/{plain}', 'PUT', {key: value for key, value in client.items() if key != 'protocolMappers'})
        observations['client-put/without-field'] = {'status': status, 'names': sorted(mapper['name'] for mapper in recording.admin_call('mappers', f'/clients/{plain}/protocol-mappers/models')[1])}
        status, _ = recording.admin_call('mappers', f'/clients/{plain}', 'PUT', {'clientId': 'plain-app', 'protocolMappers': [{'name': 'second', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper', 'config': {'included.custom.audience': 'changed'}}, {'name': 'third', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper', 'config': {}}]})
        listed = recording.admin_call('mappers', f'/clients/{plain}/protocol-mappers/models')[1]
        observations['client-put/replace'] = {'status': status, 'mappers': sorted(([mapper['name'], mapper['config']] for mapper in listed))}
        status, _ = recording.admin_call('mappers', f'/clients/{plain}', 'PUT', {'clientId': 'plain-app', 'protocolMappers': []})
        observations['client-put/empty'] = {'status': status, 'names': [mapper['name'] for mapper in recording.admin_call('mappers', f'/clients/{plain}/protocol-mappers/models')[1]]}

        token_url = base + f'/realms/{name}/protocol/openid-connect/token'
        _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'test-app'), ('client_secret', secret)])
        access = json.loads(oauth.unbase64(json.loads(body)['access_token'].split('.')[1]))
        observations['token/client-credentials'] = {'aud': audiences(access), 'azp': access.get('azp')}
        _, body = oauth.request(token_url.replace('/token', '/token/introspect'), [('token', json.loads(body)['access_token']), ('client_id', 'test-app'), ('client_secret', secret)])
        observations['token/introspection'] = {'active': json.loads(body)['active'], 'aud': audiences(json.loads(body))}
        recording.new_user('mappers', 'alice')
        browser = recording.browser('mappers')
        browser.client = 'id-app'
        tokens = browser.exchange(browser.sign_in('alice', recording.password))
        access = json.loads(oauth.unbase64(tokens['access_token'].split('.')[1]))
        identity = json.loads(oauth.unbase64(tokens['id_token'].split('.')[1]))
        observations['token/code-flow'] = {'access_aud': audiences(access), 'id_aud': audiences(identity)}
        recording.admin_call('mappers', f'/clients/{app}', 'PUT', {'clientId': 'test-app', 'enabled': False})
        tokens = recording.browser('mappers')
        tokens.client = 'id-app'
        tokens = tokens.exchange(tokens.sign_in('alice', recording.password))
        access = json.loads(oauth.unbase64(tokens['access_token'].split('.')[1]))
        observations['token/disabled-audience-client'] = {'access_aud': audiences(access)}
        del public
        scope = 'Protocol mappers in client creation and update, the protocol-mappers models, protocol and add-models resources with their errors, and the audience mapper in client-credentials, introspection and code-flow tokens.'
        normalization = 'Realm names are replaced with {realm-<key>} and the client id in Location headers with {client}; mapper ids are kept as comparisons; audiences are sorted.'
        return recording.finish(observations, 'protocol-mapper-observations.json', record, scope, normalization)
    finally:
        recording.delete_realms()


if __name__ == '__main__':
    oauth.main(run)
