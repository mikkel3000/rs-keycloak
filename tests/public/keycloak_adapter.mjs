// Client compatibility harness; no server and no credentials on disk or logs.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

let stage = "setup";
try {
    const input = JSON.parse(readFileSync(0, 'utf8'));
    const { default: Keycloak } = await import(pathToFileURL(process.argv[2]).href);
    const values = new Map();
    globalThis.isSecureContext = true;
    globalThis.localStorage = {
        setItem: (key, value) => values.set(key, value),
        getItem: key => values.get(key) ?? null,
        removeItem: key => values.delete(key),
    };
    globalThis.window = {
        location: { href: 'https://client.example.test/callback' },
        history: { state: null, replaceState: (_state, _unused, url) => { window.location.href = url; } },
        setTimeout, clearTimeout,
    };
    const transport = globalThis.fetch;
    globalThis.fetch = (url, options) => {
        const address = new URL(url);
        if (address.origin !== 'https://login.example.test') {
            throw new Error('Unexpected adapter destination');
        }
        return transport(input.transport + address.pathname + address.search, options);
    };
    const config = {
        url: 'https://login.example.test' + input.prefix,
        realm: 'master', clientId: input.client,
    };
    const options = {
        adapter: { redirectUri: () => 'https://client.example.test/callback' },
        checkLoginIframe: false,
    };
    let adapter = new Keycloak(config);
    let initialized;
    if (input.login) {
        stage = "authorization";
        await adapter.init(options);
        const loginUrl = await adapter.createLoginUrl({ redirectUri: 'https://client.example.test/callback' });
        const page = await fetch(loginUrl);
        const html = await page.text();
        const action = html.match(/<form[^>]+action="([^"]+)"/)[1].replaceAll('&amp;', '&');
        const cookie = page.headers.get('set-cookie').split(';')[0];
        stage = "password";
        const login = await fetch(new URL(action, 'https://login.example.test'), {
            method: 'POST', redirect: 'manual', headers: { Cookie: cookie },
            body: new URLSearchParams({ username: input.login.username, password: input.login.password }),
        });
        if (login.status !== 302) throw new Error('Login did not redirect');
        window.location.href = login.headers.get('location');
        if (!new URL(window.location.href).hash.includes('code=')) throw new Error('Missing fragment code');
        stage = "callback";
        adapter = new Keycloak(config);
        initialized = await adapter.init(options);
    } else {
        stage = "token-loading";
        initialized = await adapter.init({
            ...options, token: input.tokens.access_token,
            refreshToken: input.tokens.refresh_token, idToken: input.tokens.id_token,
        });
    }
    stage = "refresh";
    if (!initialized || adapter.refreshTokenParsed.typ !== 'Refresh') {
        throw new Error('Adapter did not accept token set');
    }
    if (!await adapter.updateToken(-1)) throw new Error('Adapter did not refresh');
    // Private pipe to the parent test, which never prints this payload.
    process.stdout.write(JSON.stringify({
        access_token: adapter.token, refresh_token: adapter.refreshToken,
        id_token: adapter.idToken,
    }));
} catch {
    process.stderr.write('Pinned Keycloak adapter check failed at ' + stage + '\n');
    process.exitCode = 1;
}
