#!/usr/bin/env python3
"""Capture pinned Keycloak email verification behavior."""
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
from execute_actions import mail_summary
from otp import page
from tokens import send

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from smtp_sink import SmtpSink  # noqa: E402


def phrases(html):
    """Keyword evidence from a page, without retaining its markup."""
    text = html.lower()
    return sorted(phrase for phrase in ('already been verified', 'been verified', 'confirm validity', 'click here to proceed', 'expired', 'invalid') if phrase in text)


def run(base, bootstrap_secret, record=False):
    token_url = base + '/realms/master/protocol/openid-connect/token'
    _, body = oauth.request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', bootstrap_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    callback = base + '/callback'
    password = secrets.token_urlsafe(30)
    observations = {}
    auth = {'Authorization': 'Bearer ' + admin, 'Content-Type': 'application/json'}
    with SmtpSink() as sink:
        smtp = {'host': '127.0.0.1', 'port': str(sink.port), 'from': 'noreply@example.invalid', 'fromDisplayName': 'Reference Realm'}
        user = {'username': 'reference-user', 'enabled': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'emailVerified': False, 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}
        other = {'username': 'other-user', 'enabled': True, 'firstName': 'Other', 'lastName': 'User', 'email': 'other@example.invalid', 'emailVerified': False}
        oauth.request(base + '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'verifyEmail': True, 'smtpServer': smtp, 'clients': [{'clientId': 'verify-app', 'publicClient': True, 'redirectUris': [callback]}], 'users': [user, other]}, admin, expected=201)
        try:
            users = base + '/admin/realms/' + realm + '/users'
            user_id = json.loads(send_raw(users + '?username=reference-user&exact=true', 'GET', None, auth)[2])[0]['id']
            other_id = json.loads(send_raw(users + '?username=other-user&exact=true', 'GET', None, auth)[2])[0]['id']
            policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('http', 'https', 'wss'))
            browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), oauth.Redirects())
            query = urllib.parse.urlencode({'client_id': 'verify-app', 'redirect_uri': callback, 'response_type': 'code', 'scope': 'openid', 'state': 's', 'code_challenge': 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'code_challenge_method': 'S256'})
            form = oauth.Form()
            form.feed(send(base + '/realms/' + realm + '/protocol/openid-connect/auth?' + query, opener=browser)[2].decode())
            response = send(form.action, list((form.fields | {'username': 'reference-user', 'password': password, 'credentialId': ''}).items()), opener=browser)
            observations['login/after-password'], _ = page(response)
            text = response[2].decode()
            observations['login/after-password']['resend_link'] = bool(re.search(r'href="[^"]*login-actions/required-action[^"]*"', text))
            received = sink.wait(1)
            observations['mail/after-password'] = {'count': len(received)}
            observations['mail/message'], link = mail_summary(received[-1], base, realm)
            rep = json.loads(send_raw(users + '/' + user_id, 'GET', None, auth)[2])
            observations['admin/user-before-link'] = {'emailVerified': rep['emailVerified'], 'requiredActions': rep['requiredActions']}
            observations['link/same-browser'], _ = page(send(link, opener=browser))
            rep = json.loads(send_raw(users + '/' + user_id, 'GET', None, auth)[2])
            observations['admin/user-after-link'] = {'emailVerified': rep['emailVerified'], 'requiredActions': rep['requiredActions']}
            response = send(link, opener=urllib.request.build_opener(oauth.Redirects()))
            observations['link/reused'], _ = page(response)
            observations['link/reused']['phrases'] = phrases(response[2].decode())
            status, _, body = send_raw(users + '/' + other_id + '/send-verify-email', 'PUT', None, auth)
            observations['admin/send-verify-email'] = {'status': status, 'body': json.loads(body) if body else None}
            received = sink.wait(2)
            observations['mail/admin-sent'], admin_link = mail_summary(received[-1], base, realm)
            fresh = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), oauth.Redirects())
            response = send(admin_link, opener=fresh)
            observations['link/admin-sent'], _ = page(response)
            observations['link/admin-sent']['phrases'] = phrases(response[2].decode())
            proceed = re.search(r'href="([^"]*login-actions/action-token[^"]*)"', response[2].decode())
            observations['link/admin-sent']['proceed_link'] = proceed is not None
            if proceed:
                response = send(urllib.parse.urljoin(admin_link, proceed.group(1).replace('&amp;', '&')), opener=fresh)
                observations['link/admin-proceed'], _ = page(response)
                observations['link/admin-proceed']['phrases'] = phrases(response[2].decode())
            rep = json.loads(send_raw(users + '/' + other_id, 'GET', None, auth)[2])
            observations['admin/other-after-link'] = {'emailVerified': rep['emailVerified']}
            status, _, body = send_raw(users + '/00000000-0000-0000-0000-000000000000/send-verify-email', 'PUT', None, auth)
            observations['admin/send-unknown-user'] = {'status': status, 'body': json.loads(body) if body else None}
            baseline = pathlib.Path(__file__).with_name('verify-email-observations.json')
            assert record or baseline.exists(), 'reference verify email baseline missing'
            if not record:
                expected = json.loads(baseline.read_text())['observations']
                assert observations.keys() == expected.keys(), 'reference verify email case inventory changed'
                for label in observations:
                    assert observations[label] == expected[label], f'reference verify email case changed: {label}'
            lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
            return {'keycloak_version': lock['keycloak']['version'], 'source_revision': lock['keycloak']['source_revision'], 'paired': False, 'scope': 'VERIFY_EMAIL at login and admin send-verify-email through a local SMTP sink: pages, message shape, link effects and reuse; no links or tokens retained.', 'normalization': 'Pages are reduced to form id and field names; mail to headers, parts and link shape.', 'observations': observations}
        finally:
            oauth.request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


if __name__ == '__main__':
    try:
        oauth.main(run)
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference verify email check failed: {detail}') from None
