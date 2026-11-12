#!/usr/bin/env python3
"""Capture pinned Keycloak's realm creation with a given `id`, as the
upstream test framework's RealmSupplier sends it, and realm
representations over 16 KiB."""
import json
import re
import secrets

import oauth
from recording import Recording

UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


def summary(status, body):
    parsed = json.loads(body) if body else None
    return {'status': status, 'body': parsed if isinstance(parsed, dict) and len(parsed) <= 2 else None}


def large_texts():
    # About 40 KiB of realm localization texts.
    return {'en': {f'key{index:04d}': 'x' * 120 for index in range(320)}}


def run(base, bootstrap_secret, record=False):
    recording = Recording(base, bootstrap_secret, ['given', 'blank', 'other', 'large'])
    names = recording.names
    observations = {}

    def create(payload):
        status, _, body = recording.call('POST', '/admin/realms', {'Authorization': 'Bearer ' + recording.admin, 'Content-Type': 'application/json'}, json.dumps(payload).encode())
        return summary(status, body)

    def read(key):
        return recording.admin_call(key, '')

    given = 'id-' + secrets.token_hex(6)
    try:
        observations['create/given-id'] = create({'realm': names['given'], 'id': given, 'enabled': True})
        status, realm = read('given')
        observations['read/given-id'] = {'status': status, 'id_is_given': realm['id'] == given, 'enabled': realm['enabled']}
        status, listed = recording.call('GET', '/admin/realms', {'Authorization': 'Bearer ' + recording.admin})[::2]
        observations['list/given-id'] = {'status': status, 'listed_with_id': any(item['realm'] == names['given'] and item['id'] == given for item in json.loads(listed))}
        for label, value in (('semicolon', 'in;valid'), ('slash', 'in/valid'), ('hash', 'in#valid')):
            observations[f'create/reserved-{label}'] = create({'realm': names['other'], 'id': value})
        observations['create/taken-id'] = create({'realm': names['other'], 'id': given})
        observations['create/blank-id'] = create({'realm': names['blank'], 'id': '  '})
        status, realm = read('blank')
        observations['read/blank-id'] = {'status': status, 'generated_uuid': bool(UUID.match(realm['id']))}
        status, _ = recording.admin_call('given', '', 'PUT', {'realm': names['given'], 'id': 'changed-' + secrets.token_hex(4), 'enabled': True})
        _, realm = read('given')
        observations['update/other-id'] = {'status': status, 'id_kept': realm['id'] == given}
        status, _ = recording.admin_call('given', '', 'PUT', realm)
        observations['update/own-representation'] = {'status': status}
        texts = large_texts()
        observations['create/large'] = create({'realm': names['large'], 'enabled': True, 'localizationTexts': texts})
        status, stored = recording.admin_call('large', '/localization/en')
        observations['read/large-texts'] = {'status': status, 'texts': len(stored)}
        status, _ = recording.admin_call('large', '', 'PUT', {'realm': names['large'], 'displayName': 'Large', 'localizationTexts': texts})
        _, realm = read('large')
        observations['update/large'] = {'status': status, 'display_name': realm.get('displayName')}
        scope = 'Realm creation with a given, reserved-character, taken and blank id; reading the id back, the id in a realm update, and realm create and update bodies over 16 KiB.'
        normalization = 'Realm names are replaced with {realm-<key>}; ids are kept only as comparisons with the given id or a UUID check.'
        return recording.finish(observations, 'realm-id-observations.json', record, scope, normalization)
    finally:
        for key, name in names.items():
            if recording.admin_call(key, '')[0] == 200:
                oauth.request(base + '/admin/realms/' + name, token=recording.admin, method='DELETE', expected=204)


if __name__ == '__main__':
    oauth.main(run)
