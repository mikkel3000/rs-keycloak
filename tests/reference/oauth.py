#!/usr/bin/env python3
"""Exercise pinned Keycloak public login forms and code+PKCE with disposable data."""
import argparse
import base64
import hashlib
import html.parser
import http.cookiejar
import json
import os
import pathlib
import secrets
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


class Form(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
        self.fields = {}
        self.active = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form' and attrs.get('id') == 'kc-form-login':
            self.active = True
            self.action = attrs['action']
        if self.active and tag == 'input' and attrs.get('name') and attrs.get('type') == 'hidden':
            self.fields[attrs['name']] = attrs.get('value', '')

    def handle_endtag(self, tag):
        if tag == 'form':
            self.active = False


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).path == '/callback':
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request(url, data=None, token=None, opener=None, method=None, expected=200, basic=None):
    headers = {}
    if isinstance(data, dict):
        headers['Content-Type'] = 'application/json'
        data = json.dumps(data).encode()
    elif isinstance(data, list):
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        data = urllib.parse.urlencode(data).encode()
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if basic:
        credentials = ':'.join(urllib.parse.quote(value, safe='') for value in basic).encode()
        headers['Authorization'] = 'Basic ' + base64.b64encode(credentials).decode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        response = (opener or urllib.request.build_opener()).open(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(2 * 1024 * 1024)
        assert response.status == expected, f'HTTP status {response.status}, expected {expected}'
        return response.headers, body


def unbase64(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def verify_token(token, issuer):
    """Verify the fixture's RS256 token using upstream JWKS and OpenSSL."""
    header, payload, signature = token.split('.')
    metadata = json.loads(unbase64(header))
    assert metadata['alg'] == 'RS256', 'fixture signature algorithm'
    _, body = request(issuer + '/protocol/openid-connect/certs')
    matches = [key for key in json.loads(body)['keys'] if key['kid'] == metadata['kid'] and key['kty'] == 'RSA' and key.get('use') == 'sig']
    assert len(matches) == 1, 'unique signing key'
    key = matches[0]

    def der(tag, value):
        length = len(value)
        encoded_length = bytes([length]) if length < 128 else bytes([0x80 + (length.bit_length() + 7) // 8]) + length.to_bytes((length.bit_length() + 7) // 8, 'big')
        return bytes([tag]) + encoded_length + value

    def integer(value):
        value = unbase64(value).lstrip(b'\x00') or b'\x00'
        return der(2, (b'\x00' if value[0] & 128 else b'') + value)

    # Only serialize public RSA parameters; OpenSSL performs signature verification.
    public = der(0x30, integer(key['n']) + integer(key['e']))
    encoded = base64.b64encode(public).decode()
    pem = ('-----BEGIN RSA PUBLIC KEY-----\n' + '\n'.join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) + '\n-----END RSA PUBLIC KEY-----\n').encode()
    public_read, public_write = os.pipe()
    signature_read, signature_write = os.pipe()
    try:
        os.write(public_write, pem)
        os.close(public_write)
        public_write = None
        os.write(signature_write, unbase64(signature))
        os.close(signature_write)
        signature_write = None
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', f'/dev/fd/{public_read}', '-signature', f'/dev/fd/{signature_read}'], input=(header + '.' + payload).encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, pass_fds=(public_read, signature_read), check=False)
        assert result.returncode == 0, 'token signature verification'
    finally:
        for descriptor in (public_read, public_write, signature_read, signature_write):
            if descriptor is not None:
                os.close(descriptor)
    return json.loads(unbase64(payload))


def run(base, client_secret, confidential=False):
    _, body = request(base + '/realms/master/protocol/openid-connect/token', [('grant_type', 'client_credentials'), ('client_id', 'reference-bootstrap'), ('client_secret', client_secret)])
    admin = json.loads(body)['access_token']
    realm = 'reference-' + secrets.token_hex(6)
    password = secrets.token_urlsafe(32)
    browser_secret = secrets.token_urlsafe(40) if confidential else None
    redirect = base + '/callback'
    fixture = {'realm': realm, 'enabled': True, 'sslRequired': 'none', 'clients': [{'clientId': 'reference-browser', 'publicClient': not confidential, 'secret': browser_secret, 'serviceAccountsEnabled': confidential, 'standardFlowEnabled': True, 'directAccessGrantsEnabled': False, 'redirectUris': [redirect], 'attributes': {'pkce.code.challenge.method': 'S256'}}], 'users': [{'username': 'reference-user', 'enabled': True, 'emailVerified': True, 'firstName': 'Reference', 'lastName': 'User', 'email': 'reference@example.invalid', 'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}]}
    request(base + '/admin/realms', fixture, admin, expected=201)
    try:
        issuer = base + '/realms/' + realm
        token_url = issuer + '/protocol/openid-connect/token'
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        state, nonce = secrets.token_urlsafe(20), secrets.token_urlsafe(20)
        query = urllib.parse.urlencode({'client_id': 'reference-browser', 'redirect_uri': redirect, 'response_type': 'code', 'scope': 'openid profile', 'state': state, 'nonce': nonce, 'code_challenge': challenge, 'code_challenge_method': 'S256'})
        # Browsers treat loopback as a secure context; stdlib CookieJar does not.
        # This jar only visits the fixed loopback reference origin.
        policy = http.cookiejar.DefaultCookiePolicy(secure_protocols=('https', 'wss', 'http'))
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(policy=policy)), Redirects())
        _, body = request(issuer + '/protocol/openid-connect/auth?' + query, opener=browser)
        form = Form()
        form.feed(body.decode())
        assert form.action, 'login form missing'
        assert form.action.startswith(issuer + '/login-actions/'), 'unexpected form origin'
        fields = form.fields | {'username': 'reference-user', 'password': password, 'credentialId': ''}
        headers, _ = request(form.action, list(fields.items()), opener=browser, expected=302)
        callback = urllib.parse.urlparse(headers['Location'])
        assert callback.scheme + '://' + callback.netloc + callback.path == redirect, 'callback origin'
        result = urllib.parse.parse_qs(callback.query)
        assert result['state'] == [state] and result['iss'] == [issuer], 'callback binding'
        code = result['code'][0]
        grant = [('grant_type', 'authorization_code'), ('client_id', 'reference-browser'), ('redirect_uri', redirect), ('code', code), ('code_verifier', verifier)]
        failure_responses = {}
        if confidential:
            headers, body = request(token_url, grant, expected=401)
            failure_responses['missing_secret'] = {'status': 401, 'error': json.loads(body)['error'], 'error_description': json.loads(body).get('error_description'), 'www_authenticate': headers.get('WWW-Authenticate')}
            assert json.loads(body)['error'] == 'unauthorized_client', 'missing confidential credentials'
            headers, body = request(token_url, grant + [('client_secret', secrets.token_urlsafe(40))], expected=401)
            failure_responses['wrong_secret'] = {'status': 401, 'error': json.loads(body)['error'], 'error_description': json.loads(body).get('error_description'), 'www_authenticate': headers.get('WWW-Authenticate')}
            assert json.loads(body)['error'] == 'unauthorized_client', 'wrong confidential credentials'
            headers, body = request(token_url, [('grant_type', 'client_credentials'), ('client_id', 'reference-client-does-not-exist'), ('client_secret', secrets.token_urlsafe(40))], expected=401)
            failure_responses['unknown_client'] = {'status': 401, 'error': json.loads(body)['error'], 'error_description': json.loads(body).get('error_description'), 'www_authenticate': headers.get('WWW-Authenticate')}
            assert json.loads(body)['error'] == 'invalid_client', 'unknown confidential client'
            assert all(response['www_authenticate'] is None and response['error_description'] == 'Invalid client or Invalid client credentials' for response in failure_responses.values()), 'confidential error response shape'
            for label, identity, expected_error in [('wrong_basic_secret', 'reference-browser', 'unauthorized_client'), ('unknown_basic_client', 'reference-client-does-not-exist', 'invalid_client')]:
                headers, body = request(token_url, [('grant_type', 'client_credentials')], basic=(identity, secrets.token_urlsafe(40)), expected=401)
                failure_responses[label] = {'status': 401, 'error': json.loads(body)['error'], 'error_description': json.loads(body).get('error_description'), 'www_authenticate': headers.get('WWW-Authenticate')}
                assert json.loads(body)['error'] == expected_error, 'Basic client denial'
            grant.append(('client_secret', browser_secret))
        _, body = request(token_url, grant)
        tokens = json.loads(body)
        claims = verify_token(tokens['id_token'], issuer)
        damaged = tokens['id_token'].split('.')
        damaged[2] = ('A' if damaged[2][0] != 'A' else 'B') + damaged[2][1:]
        try:
            verify_token('.'.join(damaged), issuer)
        except AssertionError as error:
            assert str(error) == 'token signature verification', 'tampered signature failure'
        else:
            raise AssertionError('tampered signature accepted')
        access = verify_token(tokens['access_token'], issuer)
        assert access['iss'] == issuer and access['sub'] == claims['sub'], 'access token subject binding'
        assert claims['iss'] == issuer and claims['aud'] == 'reference-browser' and claims['nonce'] == nonce, 'ID claim binding'
        assert claims['exp'] > time.time() and claims['iat'] <= time.time() + 5, 'ID token times'
        _, body = request(issuer + '/protocol/openid-connect/userinfo', token=tokens['access_token'])
        assert json.loads(body)['sub'] == claims['sub'], 'userinfo subject'
        _, body = request(token_url, [('grant_type', 'refresh_token'), ('client_id', 'reference-browser'), ('refresh_token', tokens['refresh_token'])] + ([('client_secret', browser_secret)] if confidential else []))
        assert json.loads(body)['access_token'], 'refresh response'
        _, body = request(token_url, grant, expected=400)
        assert json.loads(body)['error'] == 'invalid_grant', 'code replay'
        # A fresh authorization attempt proves PKCE denial, independent of replay.
        _, body = request(issuer + '/protocol/openid-connect/auth?' + query + '&prompt=login', opener=browser)
        form = Form()
        form.feed(body.decode())
        assert form.action and form.action.startswith(issuer + '/login-actions/'), 'second login form'
        headers, _ = request(form.action, list((form.fields | {'username': 'reference-user', 'password': password, 'credentialId': ''}).items()), opener=browser, expected=302)
        denied_code = urllib.parse.parse_qs(urllib.parse.urlparse(headers['Location']).query)['code'][0]
        _, body = request(token_url, [('grant_type', 'authorization_code'), ('client_id', 'reference-browser'), ('redirect_uri', redirect), ('code', denied_code), ('code_verifier', secrets.token_urlsafe(48))] + ([('client_secret', browser_secret)] if confidential else []), expected=400)
        assert json.loads(body)['error'] == 'invalid_grant', 'wrong PKCE verifier'
        if confidential:
            _, body = request(token_url, [('grant_type', 'client_credentials')], basic=('reference-browser', browser_secret))
            service = json.loads(body)
            access = verify_token(service['access_token'], issuer)
            assert access['iss'] == issuer and access['azp'] == 'reference-browser', 'service token client binding'
            assert 'refresh_token' not in service, 'service token refresh default'
        return {'client_auth_failures': failure_responses, 'client_type': 'confidential' if confidential else 'public', 'confidential_checks': ['missing secret denial', 'wrong secret denial', 'unknown client denial', 'wrong and unknown Basic client denial', 'client_secret_post code/refresh', 'client_secret_basic service grant'] if confidential else [], 'public_login_code_pkce': 'passed', 'checks': ['public realm import', 'login form and cookies', 'S256 PKCE exchange', 'JWKS signature and tampering checks', 'state issuer nonce audience expiry binding', 'userinfo subject', 'code replay rejection', 'wrong PKCE verifier rejection', 'refresh'], 'paired': False, 'signature_verification': 'OpenSSL RS256 against public JWKS', 'browser_engine': 'HTTP form client, not browser automation'}
    finally:
        request(base + '/admin/realms/' + realm, token=admin, method='DELETE', expected=204)


def main(runner=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=pathlib.Path)
    parser.add_argument('--port', type=int, default=18081)
    if runner:
        parser.add_argument('--record', action='store_true', help='Emit redacted reference observations without comparing the checked-in baseline')
    args = parser.parse_args()
    lock = json.loads((pathlib.Path(__file__).resolve().parents[2] / 'compatibility/reference.lock').read_text())
    digest = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    assert digest == lock['keycloak']['distribution']['sha256'], 'distribution digest mismatch'
    base = f'http://127.0.0.1:{args.port}'
    with tempfile.TemporaryDirectory(prefix='rs-keycloak-oauth-') as directory:
        with tarfile.open(args.archive) as archive:
            archive.extractall(directory, filter='data')
        client_secret = secrets.token_urlsafe(40)
        env = os.environ.copy()
        env['KC_BOOTSTRAP_ADMIN_CLIENT_ID'] = 'reference-bootstrap'
        env['KC_BOOTSTRAP_ADMIN_CLIENT_SECRET'] = client_secret
        process = subprocess.Popen([str(pathlib.Path(directory) / 'keycloak-26.8.1/bin/kc.sh'), 'start-dev', '--http-host=127.0.0.1', f'--http-port={args.port}'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(180):
                if process.poll() is not None:
                    raise RuntimeError('reference exited before readiness; output suppressed to protect secrets')
                try:
                    request(base + '/realms/master/.well-known/openid-configuration')
                    break
                except (urllib.error.URLError, ConnectionError):
                    time.sleep(1)
            else:
                raise RuntimeError('reference readiness deadline')
            print(json.dumps(runner(base, client_secret, record=args.record) if runner else {'cases': [run(base, client_secret), run(base, client_secret, confidential=True)], 'paired': False}))
        finally:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # URL/error bodies can carry login codes and tokens: never print them.
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        raise SystemExit(f'reference OAuth check failed: {detail}') from None
