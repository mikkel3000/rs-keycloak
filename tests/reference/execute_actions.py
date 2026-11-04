#!/usr/bin/env python3
"""Capture pinned Keycloak execute-actions-email and action-token behavior."""
import http.cookiejar
import json
import pathlib
import re
import secrets
import sys
import urllib.parse
import urllib.request

import oauth
from admin_realms import send_raw
from otp import page
from tokens import login, send

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from smtp_sink import SmtpSink  # noqa: E402


def mail_summary(received, base, realm):
    message = received['message']
    text = message.get_body(preferencelist=('plain',)).get_content()
    links = re.findall(r'https?://\S+', text)
    link = next((url for url in links if '/login-actions/action-token' in url), None)
    parsed = urllib.parse.urlsplit(link) if link else None
    return {
        'to': received['to'],
        'from_header': str(message['From']),
        'subject': str(message['Subject']),
        'multipart': message.is_multipart(),
        'parts': sorted(part.get_content_type() for part in message.walk() if not part.is_multipart()),
        'link_path': parsed.path.replace(realm, '{realm}') if parsed else None,
        'link_params': sorted(urllib.parse.parse_qs(parsed.query)) if parsed else None,
    }, link


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, bare = 'reference-' + secrets.token_hex(6), 'reference-' + secrets.token_hex(6)
    callback = base + '/callback'
    observations = {}
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    with SmtpSink() as sink:
        smtp = {'host': '127.0.0.1', 'port': str(sink.port), 'from': 'noreply@example.invalid', 'fromDisplayName': 'Reference Realm'}
        users = [{'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': secrets.token_urlsafe(30), 'temporary': False}]},
                 {'username': 'no-email', 'enabled': True, 'firstName': 'No', 'lastName': 'Email'}]
        oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'smtpServer': smtp, 'clients': [{'clientId': 'mail-app', 'publicClient': True, 'redirectUris': [callback]}], 'users': users}, admin, expected=201)
        oauth.request(base + '/admin/realms', {'realm': bare, 'enabled': True, 'sslRequired': 'none', 'users': [users[0]]}, admin, expected=201)
        try:
            listing = base + '/admin/realms/{}/users?username={}&exact=true'
            user_id = json.loads(send_raw(listing.format(realm, 'reference-user'), 'GET', None, auth)[2])[0]['id']
            no_email = json.loads(send_raw(listing.format(realm, 'no-email'), 'GET', None, auth)[2])[0]['id']
            bare_user = json.loads(send_raw(listing.format(bare, 'reference-user'), 'GET', None, auth)[2])[0]['id']
            execute = base + '/admin/realms/{}/users/{}/execute-actions-email'

            def call(label, url, actions):
                status, headers, body = send_raw(url, 'PUT', json.dumps(actions).encode(), auth)
                parsed = json.loads(body) if body else None
                observations[label] = {'status': status, 'body': parsed}

            realm_rep = json.loads(send_raw(base + '/admin/realms/' + realm, 'GET', None, auth)[2])
            observations['admin/realm-smtp'] = {'fields': sorted(realm_rep.get('smtpServer', {}))}
            call('send/no-email', execute.format(realm, no_email), ['UPDATE_PASSWORD'])
            call('send/no-smtp', execute.format(bare, bare_user), ['UPDATE_PASSWORD'])
            call('send/unknown-action', execute.format(realm, user_id), ['NOT_AN_ACTION'])
            call('send/success', execute.format(realm, user_id), ['UPDATE_PASSWORD'])
            received = sink.wait(1)
            observations['mail/count-after-errors'] = {'count': len(received)}
            observations['mail/message'], link = mail_summary(received[-1], base, realm)
            policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https', 'wss'))
            browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), oauth.Redirects())
            response = send(link, opener=browser)
            observations['link/first-page'], form = page(response)
            steps = 0
            while form and form['id'] != 'kc-passwd-update-form' and steps < 3:
                proceed = re.search(r'href="([^"]*login-actions/action-token[^"]*)"', response[2].decode())
                if not proceed:
                    break
                response = send(urllib.parse.urljoin(link, proceed.group(1).replace('&amp;', '&')), opener=browser)
                observations[f'link/proceed-{steps}'], form = page(response)
                steps += 1
            chosen = secrets.token_urlsafe(30)
            response = send(urllib.parse.urljoin(base, form['action']), list((form['fields'] | {'password-new': chosen, 'password-confirm': chosen}).items()), opener=browser)
            observations['link/after-update'], _ = page(response)
            observations['link/after-update']['text'] = 'account has been updated' in response[2].decode().lower()
            response = send(link, opener=urllib.request.build_opener(oauth.Redirects()))
            observations['link/reused'], _ = page(response)
            observations['link/reused']['text'] = re.findall(r'(expired|already been used|invalid)', response[2].decode().lower())[:1]
            tokens, _ = login(base + '/realms/' + realm, 'mail-app', None, chosen)
            observations['login/new-password'] = {'signed_in': bool(tokens.get('access_token'))}
            baseline = pathlib.Path(__file__).with_name('execute-actions-observations.json')
            assert record or baseline.exists(), 'reference execute actions baseline missing'
            if not record:
                expected = json.loads(baseline.read_text())['observations']
                assert observations.keys() == expected.keys(), 'reference execute actions case inventory changed'
                for label in observations:
                    assert observations[label] == expected[label], f'reference execute actions case changed: {label}'
            lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
            return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Admin execute-actions-email for UPDATE_PASSWORD through a local SMTP sink: errors, message shape, action-token pages, link reuse and sign-in; no tokens, links or passwords retained.', 'normalization': 'Mail is reduced to recipients, headers, MIME parts and the link path and parameter names.', 'observations': observations}
        finally:
            for name in (realm, bare):
                oauth.request(base + '/admin/realms/' + name, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference execute actions check failed: {detail}') from None
