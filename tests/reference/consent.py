#!/usr/bin/env python3
"""Capture pinned Keycloak OAuth consent behavior via public HTTP only."""
import base64
import hashlib
import html.parser
import http.cookiejar
import json
import pathlib
import secrets
import urllib.parse
import urllib.request

import oauth
from admin_realms import send_raw
from tokens import send


class AnyForm(html.parser.HTMLParser):
    """Collects the first form's action, hidden fields and submit buttons."""

    def __init__(self):
        super().__init__()
        self.action, self.fields, self.buttons, self.depth = None, {}, [], 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form' and self.action is None:
            self.action, self.depth = attrs.get('action'), 1
        elif self.depth and tag == 'input' and attrs.get('type') == 'hidden' and attrs.get('name'):
            self.fields[attrs['name']] = attrs.get('value', '')
        elif self.depth and attrs.get('type') == 'submit' and attrs.get('name'):
            self.buttons.append(attrs['name'])

    def handle_endtag(self, tag):
        if tag == 'form':
            self.depth = 0


def page_kind(status, body):
    text = body.decode(errors='replace')
    if 'kc-form-login' in text:
        return 'login'
    if 'kc-oauth' in text or 'consent' in text.lower():
        return 'consent'
    return 'other'


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, password = 'reference-' + secrets.token_hex(6), secrets.token_urlsafe(40)
    callback = base + '/callback'
    client = {'clientId': 'consent-app', 'publicClient': True, 'consentRequired': True, 'standardFlowEnabled': True, 'redirectUris': [callback], 'attributes': {'pkce.code.challenge.method': 'S256'}}
    user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
    oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [client], 'users': [user]}, admin, expected=201)
    observations = {}
    issuer = base + '/realms/' + realm
    auth = {'Authorization': 'Bearer ' + admin}
    user_id = json.loads(send_raw(base + '/admin/realms/' + realm + '/users?username=reference-user&exact=true', 'GET', None, auth)[2])[0]['id']
    consents = '/admin/realms/' + realm + '/users/' + user_id + '/consents'

    def browser():
        policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https', 'wss'))
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), oauth.Redirects())

    def authorize(opener, **extra):
        challenge = base64.urlsafe_b64encode(hashlib.sha256(secrets.token_bytes(16)).digest()).rstrip(b'=').decode()
        query = urllib.parse.urlencode(dict({'client_id': 'consent-app', 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': challenge, 'code_challenge_method': 'S256'}, **extra))
        return send(issuer + '/protocol/openid-connect/auth?' + query, opener=opener)

    def summarize(response):
        status, headers, body = response
        result = {'status': status}
        if status in (302, 303):
            params = urllib.parse.parse_qs(urllib.parse.urlsplit(headers['Location']).query)
            result['location_params'] = sorted(params)
            result['error'] = params.get('error', [None])[0]
        else:
            result['page'] = page_kind(status, body)
            form = AnyForm()
            form.feed(body.decode(errors='replace'))
            result['buttons'] = sorted(form.buttons)
        return result

    def submit_password(opener, response):
        form = oauth.Form()
        form.feed(response[2].decode())
        return send(form.action, list((form.fields | {'username': 'reference-user', 'password': password, 'credentialId': ''}).items()), opener=opener)

    def submit_consent(opener, response, button):
        form = AnyForm()
        form.feed(response[2].decode())
        return send(urllib.parse.urljoin(issuer, form.action), list((form.fields | {button: button}).items()), opener=opener)

    try:
        first = browser()
        after_password = submit_password(first, authorize(first))
        observations['consent/after-password'] = summarize(after_password)
        observations['consent/deny'] = summarize(submit_consent(first, after_password, 'cancel'))
        observations['admin/consents-after-deny'] = {'count': len(json.loads(send_raw(base + consents, 'GET', None, auth)[2]))}
        second = browser()
        after_password = submit_password(second, authorize(second))
        observations['consent/accept'] = summarize(submit_consent(second, after_password, 'accept'))
        granted = json.loads(send_raw(base + consents, 'GET', None, auth)[2])
        observations['admin/consents-after-accept'] = {'count': len(granted), 'fields': sorted(granted[0]) if granted else [], 'client': granted[0].get('clientId') if granted else None, 'scopes': sorted(granted[0].get('grantedClientScopes', [])) if granted else []}
        third = browser()
        observations['consent/remembered'] = summarize(submit_password(third, authorize(third)))
        observations['consent/prompt-consent'] = summarize(authorize(third, prompt='consent'))
        observations['admin/revoke-consent'] = {'status': send_raw(base + consents + '/consent-app', 'DELETE', None, auth)[0]}
        observations['admin/revoke-unknown'] = {'status': send_raw(base + consents + '/missing-app', 'DELETE', None, auth)[0]}
        fourth = browser()
        observations['consent/after-revoke'] = summarize(submit_password(fourth, authorize(fourth)))
        baseline = pathlib.Path(__file__).with_name('consent-observations.json')
        assert record or baseline.exists(), 'reference consent baseline missing'
        if not record:
            expected = json.loads(baseline.read_text())['observations']
            assert observations.keys() == expected.keys(), 'reference consent case inventory changed'
            for label in observations:
                assert observations[label] == expected[label], f'reference consent case changed: {label}'
        lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
        return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Consent screen after password login, deny, accept, remembered consent, prompt=consent, and admin consent listing and revocation; page kinds, button names and redirect shapes only.', 'normalization': 'Page HTML is reduced to its kind and submit button names; codes are not retained.', 'observations': observations}
    finally:
        oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference consent check failed: {detail}') from None
