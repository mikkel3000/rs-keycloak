#!/usr/bin/env python3
"""Capture pinned Keycloak forgot-password (reset credentials) behavior."""
import http.cookiejar
import json
import pathlib
import re
import secrets
import sys
import urllib.parse
import urllib.request

import oauth
from execute_actions import mail_summary
from otp import page
from tokens import login, send

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from smtp_sink import SmtpSink  # noqa: E402


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm, closed = 'reference-' + secrets.token_hex(6), 'reference-' + secrets.token_hex(6)
    callback = base + '/callback'
    observations = {}
    with SmtpSink() as sink:
        smtp = {'host': '127.0.0.1', 'port': str(sink.port), 'from': 'noreply@example.invalid', 'fromDisplayName': 'Reference Realm'}
        user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': True, 'credentials': [{'type': 'password', 'value': secrets.token_urlsafe(30), 'temporary': False}]}
        client = {'clientId': 'reset-app', 'publicClient': True, 'redirectUris': [callback]}
        oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'resetPasswordAllowed': True, 'smtpServer': smtp, 'clients': [client], 'users': [user]}, admin, expected=201)
        oauth.request(base + '/admin/realms', {'realm': closed, 'enabled': True, 'sslRequired': 'none', 'smtpServer': smtp, 'clients': [client], 'users': [user]}, admin, expected=201)
        try:
            def browser():
                policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https', 'wss'))
                return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), oauth.Redirects())

            def login_page(opener, name):
                query = urllib.parse.urlencode({'client_id': 'reset-app', 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'code_challenge_method': 'S256'})
                return send(base + '/realms/' + name + '/protocol/openid-connect/auth?' + query, opener=opener)

            def reset_link(response):
                match = re.search(r'href="([^"]*login-actions/reset-credentials[^"]*)"', response[2].decode())
                return urllib.parse.urljoin(base, match.group(1).replace('&amp;', '&')) if match else None

            observations['closed/login-has-link'] = {'link': reset_link(login_page(browser(), closed)) is not None}
            opener = browser()
            link = reset_link(login_page(opener, realm))
            observations['open/login-has-link'] = {'link': link is not None, 'path': urllib.parse.urlsplit(link).path.replace(realm, '{realm}')}
            observations['request/form'], form = page(send(link, opener=opener))
            response = send(urllib.parse.urljoin(base, form['action']), list((form['fields'] | {'username': 'nobody-here'}).items()), opener=opener)
            observations['request/unknown-user'], _ = page(response)
            observations['request/unknown-user']['sent_text'] = 'you should receive an email' in response[2].decode().lower()
            observations['mail/after-unknown'] = {'count': len(sink.received)}
            opener = browser()
            _, form = page(send(reset_link(login_page(opener, realm)), opener=opener))
            response = send(urllib.parse.urljoin(base, form['action']), list((form['fields'] | {'username': 'reference-user'}).items()), opener=opener)
            observations['request/known-user'], _ = page(response)
            observations['request/known-user']['sent_text'] = 'you should receive an email' in response[2].decode().lower()
            received = sink.wait(1)
            observations['mail/message'], mail_link = mail_summary(received[-1], base, realm)
            response = send(mail_link, opener=opener)
            observations['link/first-page'], form = page(response)
            chosen = secrets.token_urlsafe(30)
            response = send(urllib.parse.urljoin(base, form['action']), list((form['fields'] | {'password-new': chosen, 'password-confirm': chosen}).items()), opener=opener)
            observations['link/after-update'], _ = page(response)
            observations['link/reused'], _ = page(send(mail_link, opener=browser()))
            tokens, _ = login(base + '/realms/' + realm, 'reset-app', None, chosen)
            observations['login/new-password'] = {'signed_in': bool(tokens.get('access_token'))}
            baseline = pathlib.Path(__file__).with_name('reset-credentials-observations.json')
            assert record or baseline.exists(), 'reference reset credentials baseline missing'
            if not record:
                expected = json.loads(baseline.read_text())['observations']
                assert observations.keys() == expected.keys(), 'reference reset credentials case inventory changed'
                for label in observations:
                    assert observations[label] == expected[label], f'reference reset credentials case changed: {label}'
            lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
            return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'Forgot-password from the login page through a local SMTP sink: link visibility, request form, known and unknown users, message shape, link pages, reuse and sign-in; no links, tokens or passwords retained.', 'normalization': 'Pages are reduced to form id and field names; mail to headers, parts and link shape.', 'observations': observations}
        finally:
            for name in (realm, closed):
                oauth.request(base + '/admin/realms/' + name, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference reset credentials check failed: {detail}') from None
