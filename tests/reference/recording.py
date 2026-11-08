"""Shared parts of the login recorders: the admin token, realms made for
one run and removed after it, a browser per realm, and the baseline
comparison with base URL and realm names as placeholders."""
import http.client
import json
import pathlib
import secrets
import sys
import urllib.parse

import oauth

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from login_browser import Browser  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]


class Recording:
    """Realms named `<prefix>-<key>` on the reference at `base`."""

    def __init__(self, base, bootstrap_secret, keys):
        self.base = base
        self.location = urllib.parse.urlsplit(base)
        token_url = base + '/realms/master/protocol/openid-connect/token'
        _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
        self.admin = json.loads(body)['access_token']
        prefix = 'reference-' + secrets.token_hex(6)
        self.names = {key: f'{prefix}-{key}' for key in keys}
        self.password = secrets.token_urlsafe(30)
        self.callback = base + '/callback'

    def call(self, method, path, headers=None, body=None):
        connection = http.client.HTTPConnection(self.location.hostname, self.location.port, timeout=15)
        try:
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read()
        finally:
            connection.close()

    def admin_call(self, key, path, method='GET', payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        status, _, body = self.call(method, f'/admin/realms/{self.names[key]}' + path, {'Authorization': 'Bearer ' + self.admin, 'Content-Type': 'application/json'}, data)
        try:
            return status, json.loads(body) if body else None
        except ValueError:
            return status, body.decode()

    def create_realms(self, settings):
        clients = [{'clientId': 'login-app', 'publicClient': True, 'redirectUris': [self.callback]}]
        for key, extra in settings.items():
            oauth.request(self.base + '/admin/realms', {'realm': self.names[key], 'enabled': True, 'sslRequired': 'none', 'clients': clients} | extra, self.admin, expected=201)

    def delete_realms(self):
        for name in self.names.values():
            oauth.request(self.base + '/admin/realms/' + name, token=self.admin, method='DELETE', expected=204)

    def browser(self, key):
        return Browser(self.call, self.base, self.names[key], self.callback)

    def new_user(self, key, username, extra=None, password=True):
        """Makes a user with a name, an email and the password; fields
        `extra` sets to None are left out."""
        user = {'username': username, 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': username.split('@')[0] + '@example.invalid', 'emailVerified': True} | (extra or {})
        user = {field: value for field, value in user.items() if value is not None}
        if password:
            user['credentials'] = [{'type': 'password', 'value': self.password, 'temporary': False}]
        status, body = self.admin_call(key, '/users', 'POST', user)
        assert status == 201, f'user creation {status} for {key}/{username}: {body}'
        _, found = self.admin_call(key, '/users?exact=true&username=' + urllib.parse.quote(username))
        return found[0]['id']

    def finish(self, observations, baseline, record, scope, normalization):
        observations = json.loads(json.dumps(observations).replace(self.base, '{base}'))
        for key in sorted(self.names, key=lambda item: -len(self.names[item])):
            name = self.names[key]
            text = json.dumps(observations).replace(name, '{realm-' + key + '}')
            # Mails name a realm without a display name capitalized.
            observations = json.loads(text.replace(name[0].upper() + name[1:], '{Realm-' + key + '}'))
        path = pathlib.Path(__file__).with_name(baseline)
        assert record or path.exists(), f'reference baseline {baseline} missing'
        if not record:
            expected = json.loads(path.read_text())['observations']
            assert observations.keys() == expected.keys(), f'reference case inventory changed in {baseline}'
            for label in observations:
                assert observations[label] == expected[label], f'reference case changed in {baseline}: {label}: {observations[label]}'
        lock = json.loads((ROOT / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': scope, 'normalization': normalization, 'observations': observations}
