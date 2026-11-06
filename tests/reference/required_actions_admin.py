#!/usr/bin/env python3
"""Capture pinned Keycloak required action administration."""
import json
import pathlib
import secrets

import oauth
from admin_realms import send_raw
from tokens import login


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(30)
    callback = base + '/callback'
    user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'requiredActions': ['UPDATE_PASSWORD'], 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [{'clientId': 'user-app', 'publicClient': True, 'redirectUris': [callback]}], 'users': [user]}, admin, expected=201)
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    actions = base + f'/admin/realms/{realm}/authentication/required-actions'
    observations = {}
    try:
        status, _, body = send_raw(actions, 'GET', None, auth)
        listed = json.loads(body)
        observations['list'] = {'status': status, 'fields': sorted({field for item in listed for field in item}), 'actions': [[item['alias'], item['name'], item['providerId'], item['enabled'], item['defaultAction'], item['priority']] for item in listed]}
        status, _, body = send_raw(actions + '/UPDATE_PASSWORD', 'GET', None, auth)
        update_password = json.loads(body)
        observations['get'] = {'status': status, 'body': {key: update_password.get(key) for key in ('alias', 'name', 'enabled', 'defaultAction', 'priority', 'config')}}
        status, _, body = send_raw(actions + '/MISSING', 'GET', None, auth)
        observations['get/unknown'] = {'status': status, 'body': json.loads(body) if body else None}
        disabled = dict(update_password, enabled=False)
        status, _, body = send_raw(actions + '/UPDATE_PASSWORD', 'PUT', json.dumps(disabled).encode(), auth)
        observations['disable'] = {'status': status, 'empty_body': not body}
        status, _, body = send_raw(actions + '/UPDATE_PASSWORD', 'GET', None, auth)
        observations['get/after-disable'] = {'enabled': json.loads(body)['enabled']}
        try:
            tokens, _ = login(base + '/realms/' + realm, 'user-app', None, password)
            observations['login/action-disabled'] = {'completed': bool(tokens.get('access_token'))}
        except AssertionError:
            observations['login/action-disabled'] = {'completed': False}
        users = json.loads(send_raw(base + f'/admin/realms/{realm}/users?username=reference-user&exact=true', 'GET', None, auth)[2])
        observations['user/required-actions'] = {'actions': users[0]['requiredActions']}
        default = dict(update_password, enabled=True, defaultAction=True)
        status, _, _ = send_raw(actions + '/UPDATE_PASSWORD', 'PUT', json.dumps(default).encode(), auth)
        observations['default-action'] = {'status': status}
        status, headers, _ = send_raw(base + f'/admin/realms/{realm}/users', 'POST', json.dumps({'username': 'new-user', 'enabled': True}).encode(), auth)
        new_user = json.loads(send_raw(headers['Location'], 'GET', None, auth)[2])
        observations['new-user/required-actions'] = {'actions': new_user['requiredActions']}
        status, _, body = send_raw(actions + '/UPDATE_PASSWORD', 'PUT', json.dumps({'enabled': 'yes'}).encode(), auth)
        observations['update/malformed'] = {'status': status, 'body': json.loads(body) if body else None}
        status, _, body = send_raw(actions + '/MISSING', 'PUT', json.dumps({'alias': 'MISSING', 'enabled': True}).encode(), auth)
        observations['update/unknown'] = {'status': status, 'body': json.loads(body) if body else None}
        baseline = pathlib.Path(__file__).with_name('required-action-admin-observations.json')
        assert record or baseline.exists(), 'reference required action baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference required action case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference required action case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Required action listing, reading and updating, and the effect of disabling an assigned action and of default actions on new users; selected fields only.', 'normalization': 'None needed: only action fields and login outcomes are kept.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference required action check failed: {detail}') from None
