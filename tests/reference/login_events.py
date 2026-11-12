#!/usr/bin/env python3
"""Capture pinned Keycloak's stored login events: LOGIN and LOGIN_ERROR
from the login form, and listing and clearing them with GET and DELETE
/admin/realms/{realm}/events."""
import datetime
import time
import urllib.parse

import oauth
from recording import Recording

SHOWN_DETAILS = ['auth_method', 'auth_type', 'response_type', 'redirect_uri', 'consent', 'username', 'response_mode']


def event_summary(event, user_id):
    details = event.get('details', {})
    return {
        'fields': sorted(event),
        'type': event['type'],
        'error': event.get('error'),
        'client': event.get('clientId'),
        'user_is_fixture': event.get('userId') == user_id if 'userId' in event else None,
        'ip_address': event.get('ipAddress'),
        'detail_keys': sorted(details),
        'details': {key: details[key] for key in SHOWN_DETAILS if key in details},
        'code_id_is_session': details.get('code_id') == event['sessionId'] if 'sessionId' in event else None,
        'time_is_millis': event['time'] > 10 ** 12,
    }


def run(base, bootstrap_secret, record=False):
    recording = Recording(base, bootstrap_secret, ['events', 'off', 'types', 'expiry'])
    observations = {}
    try:
        recording.create_realms({'events': {'eventsEnabled': True}, 'off': {}, 'types': {'eventsEnabled': True, 'enabledEventTypes': ['LOGIN']}, 'expiry': {'eventsEnabled': True, 'eventsExpiration': 1}})
        users = {key: recording.new_user(key, 'alice') for key in recording.names}
        started = int(time.time() * 1000)
        for key in recording.names:
            recording.browser(key).sign_in('nobody', 'wrong')
            recording.browser(key).sign_in('alice', 'wrong')
            status, headers, _ = recording.browser(key).sign_in('alice', recording.password)
            assert status == 302 and '/callback?' in headers['location'], f'sign-in failed for {key}'
        finished = int(time.time() * 1000)
        status, events = recording.admin_call('events', '/events')
        observations['list/default'] = {'status': status, 'events': [event_summary(event, users['events']) for event in events]}
        status, events = recording.admin_call('events', '/events?direction=asc')
        observations['list/asc'] = {'status': status, 'types': [event['type'] for event in events], 'errors': [event.get('error') for event in events]}

        def count(label, query):
            status, events = recording.admin_call('events', '/events?' + query)
            observations[f'filter/{label}'] = {'status': status, 'types': [event['type'] for event in events] if isinstance(events, list) else events}

        count('type-login-error', 'type=LOGIN_ERROR')
        count('type-two', 'type=LOGIN&type=LOGIN_ERROR')
        count('client', 'client=login-app')
        count('client-other', 'client=other-app')
        count('user', 'user=' + users['events'])
        count('ip', 'ipAddress=127.0.0.1')
        count('max', 'max=1')
        count('first', 'first=1&max=1')
        count('first-only', 'first=2')
        count('epoch-range', f'dateFrom={started}&dateTo={finished}')
        count('epoch-before', f'dateTo={started - 1}')
        today = datetime.datetime.now(datetime.UTC).date()
        count('date-today', f'dateFrom={today}&dateTo={today}')
        count('date-past', f'dateTo={today - datetime.timedelta(days=2)}')
        count('date-invalid', 'dateFrom=yesterday')
        count('direction-invalid', 'direction=sideways')
        for key in ('off', 'types'):
            status, events = recording.admin_call(key, '/events?direction=asc')
            observations[f'list/{key}'] = {'status': status, 'types': [event['type'] for event in events]}
        time.sleep(2.2)
        status, events = recording.admin_call('expiry', '/events')
        observations['list/expired'] = {'status': status, 'types': [event['type'] for event in events]}
        status, body = recording.admin_call('events', '/events', 'DELETE')
        observations['clear'] = {'status': status, 'body': body}
        observations['list/cleared'] = {'status': recording.admin_call('events', '/events')[0], 'events': recording.admin_call('events', '/events')[1]}
        status = recording.call('GET', f"/admin/realms/{recording.names['events']}/events")[0]
        observations['list/no-token'] = {'status': status}
        status = recording.call('DELETE', f"/admin/realms/{recording.names['events']}/events")[0]
        observations['clear/no-token'] = {'status': status}
        observations['list/unknown-realm'] = {'status': recording.call('GET', '/admin/realms/no-such-realm-' + urllib.parse.quote(recording.names['events']) + '/events', {'Authorization': 'Bearer ' + recording.admin})[0]}
        scope = 'Login events stored by the login form for an unknown user, a wrong password and a sign-in, with events on, off, limited to LOGIN and with a one-second expiration; listing with each filter, order and paging parameter, and clearing.'
        normalization = 'Realm names are replaced with {realm-<key>}; ids, times and code ids are kept only as comparisons; the redirect URI keeps {base}.'
        return recording.finish(observations, 'login-event-observations.json', record, scope, normalization)
    finally:
        recording.delete_realms()


if __name__ == '__main__':
    oauth.main(run)
