#!/usr/bin/env python3
"""Capture pinned Keycloak's stored admin events: what admin API changes
record, their resource paths and representations, the events config
updates, realm creation and deletion in the master realm, and listing and
clearing them with GET and DELETE /admin/realms/{realm}/admin-events."""
import datetime
import json
import secrets
import time

import oauth
from recording import Recording


def run(base, bootstrap_secret, record=False):
    recording = Recording(base, bootstrap_secret, ['admin', 'details', 'off', 'config', 'created'])
    names = recording.names
    observations = {}
    ids = {}

    def master_call(path, method='GET', payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        status, _, body = recording.call(method, '/admin/realms/master' + path, {'Authorization': 'Bearer ' + recording.admin, 'Content-Type': 'application/json'}, data)
        return status, json.loads(body) if body else None

    master_id = master_call('')[1]['id']
    bootstrap = master_call('/clients?clientId=reference-bootstrap')[1][0]['id']
    service_account = master_call(f'/clients/{bootstrap}/service-account-user')[1]['id']
    realm_ids = {}

    def normalized(text, key):
        for label, value in sorted(ids.items(), key=lambda item: -len(item[1])):
            text = text.replace(value, '{' + label + '}')
        return text

    def summary(event, key):
        auth = event.get('authDetails', {})
        representation = event.get('representation')
        parsed = json.loads(representation) if representation else None
        shown = None
        if isinstance(parsed, dict):
            shown = {'fields': sorted(parsed), 'secret': parsed.get('secret'), 'username': parsed.get('username')}
        elif isinstance(parsed, list):
            shown = {'length': len(parsed)}
        return {
            'fields': sorted(event),
            'operation': event['operationType'],
            'resource_type': event.get('resourceType'),
            'resource_path': normalized(event['resourcePath'], key) if 'resourcePath' in event else None,
            'realm_is_own': event.get('realmId') == realm_ids.get(key),
            'auth_fields': sorted(auth),
            'auth_realm_is_master': auth.get('realmId') == master_id,
            'auth_client_is_bootstrap': auth.get('clientId') == bootstrap,
            'auth_user_is_service_account': auth.get('userId') == service_account,
            'auth_ip': auth.get('ipAddress'),
            'representation': shown,
            'time_is_millis': event['time'] > 10 ** 12,
        }

    def events(key, query='direction=asc'):
        # The reference can answer a change before its event is readable.
        time.sleep(0.3)
        status, listed = recording.admin_call(key, '/admin-events?' + query)
        return status, listed

    master_config = None
    try:
        recording.create_realms({
            'admin': {'adminEventsEnabled': True},
            'details': {'adminEventsEnabled': True, 'adminEventsDetailsEnabled': True},
            'off': {},
            'config': {},
        })
        for key in ('admin', 'details', 'off', 'config'):
            realm_ids[key] = recording.admin_call(key, '')[1]['id']
        for key in ('admin', 'details', 'off'):
            # Creating the realm's clients and settings recorded nothing yet.
            observations[f'initial/{key}'] = {'events': len(events(key)[1])}
            user = recording.new_user(key, 'alice')
            ids['user'] = user
            recording.admin_call(key, f'/users/{user}', 'PUT', {'firstName': 'Changed'})
            recording.admin_call(key, f'/users/{user}/reset-password', 'PUT', {'type': 'password', 'value': secrets.token_urlsafe(20), 'temporary': False})
            status, _, _ = recording.call('POST', f'/admin/realms/{names[key]}/clients', {'Authorization': 'Bearer ' + recording.admin, 'Content-Type': 'application/json'}, json.dumps({'clientId': 'events-app', 'secret': 'client-secret-value', 'protocolMappers': [{'name': 'audience', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper', 'config': {'included.custom.audience': 'events-app', 'access.token.claim': 'true'}}]}).encode())
            ids['client'] = recording.admin_call(key, '/clients?clientId=events-app')[1][0]['id']
            recording.admin_call(key, '/roles', 'POST', {'name': 'events-role'})
            recording.admin_call(key, '/groups', 'POST', {'name': 'events-group'})
            ids['group'] = recording.admin_call(key, '/groups?search=events-group')[1][0]['id']
            recording.admin_call(key, '', 'PUT', {'displayName': 'Fury Road'})
            duplicate = recording.admin_call(key, '/users', 'POST', {'username': 'alice'})[0]
            recording.admin_call(key, f'/users/{user}', 'DELETE')
            status, listed = events(key)
            observations[f'events/{key}'] = {'status': status, 'duplicate_status': duplicate, 'events': [summary(event, key) for event in listed]}
        status, listed = events('admin', 'direction=desc')
        observations['order/default'] = {'status': recording.admin_call('admin', '/admin-events')[0], 'same_as_desc': recording.admin_call('admin', '/admin-events')[1] == listed}

        def count(label, query):
            status, listed = events('admin', query)
            observations[f'filter/{label}'] = {'status': status, 'operations': [(event['operationType'], event.get('resourceType')) for event in listed] if isinstance(listed, list) else listed}

        count('operation-create', 'operationTypes=CREATE&direction=asc')
        count('operation-two', 'operationTypes=CREATE&operationTypes=DELETE&direction=asc')
        count('resource-user', 'resourceTypes=USER&direction=asc')
        count('path-users', 'resourcePath=users/*&direction=asc')
        count('path-exact', f"resourcePath=users/{ids['user']}&direction=asc")
        count('auth-realm', f'authRealm={master_id}&direction=asc')
        count('auth-realm-other', f"authRealm={realm_ids['admin']}&direction=asc")
        count('auth-client', f'authClient={bootstrap}&direction=asc')
        count('auth-user', f'authUser={service_account}&direction=asc')
        count('auth-ip', 'authIpAddress=127.0.0.1&direction=asc')
        count('max', 'max=2&direction=asc')
        count('first', 'first=2&max=2&direction=asc')
        today = datetime.datetime.now(datetime.UTC).date()
        count('date-today', f'dateFrom={today}&dateTo={today}&direction=asc')
        count('epoch-future', f'dateFrom={int(time.time() * 1000) + 3600000}')
        count('date-invalid', 'dateTo=tomorrow')
        count('direction-invalid', 'direction=up')

        def put_config(label, payload):
            status, _ = recording.admin_call('config', '/events/config', 'PUT', payload)
            status_list, listed = events('config')
            observations[f'config/{label}'] = {'status': status, 'events': [summary(event, 'config') for event in listed]}

        put_config('off-to-on', {'adminEventsEnabled': True, 'adminEventsDetailsEnabled': True})
        put_config('on-to-on', {'eventsEnabled': True, 'adminEventsEnabled': True, 'adminEventsDetailsEnabled': True})
        put_config('on-to-off', {'eventsEnabled': True, 'adminEventsEnabled': False, 'adminEventsDetailsEnabled': True})
        put_config('off-to-off', {'eventsEnabled': True, 'adminEventsEnabled': False, 'adminEventsDetailsEnabled': False})
        recording.admin_call('config', '', 'PUT', {'adminEventsEnabled': True})
        observations['realm-update-enabling'] = {'events': len(events('config')[1])}
        recording.admin_call('config', '', 'PUT', {'adminEventsEnabled': False})
        observations['realm-update-disabling'] = {'events': [summary(event, 'config') for event in events('config')[1]][3:]}

        master_config = master_call('/events/config')[1]
        master_call('/events/config', 'PUT', master_config | {'adminEventsEnabled': True, 'adminEventsDetailsEnabled': True})
        master_call('/admin-events', 'DELETE')
        created = names['created']
        oauth.request(base + '/admin/realms', {'realm': created, 'id': created, 'enabled': True}, recording.admin, expected=201)
        oauth.request(base + '/admin/realms/' + created, token=recording.admin, method='DELETE', expected=204)
        listed = master_call('/admin-events?direction=asc')[1]
        realm_ids['master'] = master_id
        observations['master/create-delete'] = [summary(event, 'master') for event in listed]

        status, body = recording.admin_call('admin', '/admin-events', 'DELETE')
        observations['clear'] = {'status': status, 'body': body, 'after': events('admin')[1]}
        observations['list/no-token'] = {'status': recording.call('GET', f"/admin/realms/{names['admin']}/admin-events")[0]}
        observations['clear/no-token'] = {'status': recording.call('DELETE', f"/admin/realms/{names['admin']}/admin-events")[0]}
        scope = 'Admin events recorded by user, client, role, group and realm changes with admin events off, on, and on with representations; events config changes between on and off; realm creation and deletion in the master realm; listing with each filter, order and paging parameter, and clearing.'
        normalization = 'Realm names are replaced with {realm-<key>}; user, client and group ids in resource paths with {user}, {client} and {group}; the realm and auth ids are kept as comparisons with the realm, master realm, bootstrap client and its service account; representations are kept as their field names and selected values.'
        return recording.finish(observations, 'admin-event-observations.json', record, scope, normalization)
    finally:
        if master_config is not None:
            master_call('/events/config', 'PUT', master_config)
            master_call('/admin-events', 'DELETE')
        status = recording.call('GET', '/admin/realms/' + names['created'], {'Authorization': 'Bearer ' + recording.admin})[0]
        if status == 200:
            oauth.request(base + '/admin/realms/' + names['created'], token=recording.admin, method='DELETE', expected=204)
        for key in ('admin', 'details', 'off', 'config'):
            oauth.request(base + '/admin/realms/' + names[key], token=recording.admin, method='DELETE', expected=204)


if __name__ == '__main__':
    oauth.main(run)
