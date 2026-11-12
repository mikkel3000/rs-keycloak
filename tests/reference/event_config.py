#!/usr/bin/env python3
"""Capture pinned Keycloak's realm event settings: eventsEnabled,
adminEventsEnabled and adminEventsDetailsEnabled in realm representations
and GET and PUT /admin/realms/{realm}/events/config."""
import oauth
from recording import Recording

EVENT_FIELDS = ['eventsEnabled', 'eventsExpiration', 'eventsListeners', 'enabledEventTypes', 'adminEventsEnabled', 'adminEventsDetailsEnabled']


def realm_events(realm):
    # The reference keeps event types in a hash set; the order is not part
    # of the rule.
    events = {field: realm.get(field) for field in EVENT_FIELDS}
    if events['enabledEventTypes'] is not None:
        events['enabledEventTypes'] = sorted(events['enabledEventTypes'])
    return events


def config_summary(status, config):
    if status != 200:
        return {'status': status, 'body': config}
    types = config.get('enabledEventTypes')
    return {
        'status': status,
        'fields': sorted(config),
        'settings': {field: config.get(field) for field in EVENT_FIELDS if field != 'enabledEventTypes'},
        'enabled_event_types': sorted(types) if len(types) < 10 else {'count': len(types), 'first': types[:6], 'has_client_delete_error': 'CLIENT_DELETE_ERROR' in types},
    }


def run(base, bootstrap_secret, record=False):
    recording = Recording(base, bootstrap_secret, ['plain', 'events', 'config'])
    observations = {}
    try:
        recording.create_realms({'plain': {}, 'events': {'eventsEnabled': True, 'adminEventsEnabled': True, 'adminEventsDetailsEnabled': True}, 'config': {}})
        for key in ('plain', 'events'):
            observations[f'realm/{key}'] = realm_events(recording.admin_call(key, '')[1])
            observations[f'config/{key}'] = config_summary(*recording.admin_call(key, '/events/config'))
        observations['default-event-types'] = recording.admin_call('plain', '/events/config')[1]['enabledEventTypes']

        def put_config(label, payload):
            status, body = recording.admin_call('config', '/events/config', 'PUT', payload)
            observations[f'put/{label}'] = {'status': status, 'body': body}
            observations[f'after/{label}'] = config_summary(*recording.admin_call('config', '/events/config'))
            observations[f'realm-after/{label}'] = realm_events(recording.admin_call('config', '')[1])

        put_config('enable-all', {'eventsEnabled': True, 'adminEventsEnabled': True, 'adminEventsDetailsEnabled': True})
        put_config('admin-flags-absent', {'eventsEnabled': True})
        put_config('events-absent', {'adminEventsEnabled': True})
        put_config('types', {'eventsEnabled': True, 'enabledEventTypes': ['CLIENT_DELETE', 'CLIENT_DELETE_ERROR']})
        put_config('types-empty', {'eventsEnabled': True, 'enabledEventTypes': []})
        put_config('expiration', {'eventsEnabled': True, 'eventsExpiration': 3600})
        put_config('expiration-absent', {'eventsEnabled': True})
        put_config('listeners-empty', {'eventsEnabled': True, 'eventsListeners': []})
        put_config('listeners-default', {'eventsEnabled': True, 'eventsListeners': ['jboss-logging']})
        put_config('listeners-unknown', {'eventsEnabled': True, 'eventsListeners': ['no-such-listener']})
        put_config('not-an-object', [])

        def put_realm(label, payload):
            status, body = recording.admin_call('config', '', 'PUT', payload)
            observations[f'realm-put/{label}'] = {'status': status, 'body': body}
            observations[f'realm-put-after/{label}'] = realm_events(recording.admin_call('config', '')[1])

        put_realm('flags', {'eventsEnabled': False, 'adminEventsEnabled': True, 'adminEventsDetailsEnabled': False})
        put_realm('flags-absent', {'displayName': 'Events'})
        put_realm('types', {'enabledEventTypes': ['LOGIN_ERROR']})
        put_realm('types-empty', {'enabledEventTypes': []})
        put_realm('expiration', {'eventsExpiration': 60})
        put_realm('wrong-type', {'eventsEnabled': 'yes'})
        status, _ = recording.call('GET', f"/admin/realms/{recording.names['config']}/events/config")[::2]
        observations['config/no-token'] = {'status': status}
        status, body = recording.admin_call('config', '/events/config/missing')
        observations['config/unknown-path'] = {'status': status}
        scope = 'Realm event settings in realm representations at creation and update, and the events config resource: defaults, each flag, event types, expiration, listeners and malformed bodies.'
        normalization = 'Realm names are replaced with {realm-<key>}; the default event type list is kept as its count, its first six entries and whether it has CLIENT_DELETE_ERROR.'
        return recording.finish(observations, 'event-config-observations.json', record, scope, normalization)
    finally:
        recording.delete_realms()


if __name__ == '__main__':
    oauth.main(run)
