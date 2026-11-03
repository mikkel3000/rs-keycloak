// Client compatibility harness; no server and no credentials on disk or logs.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

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
    const adapter = new Keycloak({
        url: 'https://login.example.test' + input.prefix,
        realm: 'master', clientId: input.client,
    });
    const initialized = await adapter.init({
        adapter: {}, checkLoginIframe: false,
        token: input.tokens.access_token,
        refreshToken: input.tokens.refresh_token,
        idToken: input.tokens.id_token,
    });
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
    process.stderr.write('Pinned Keycloak adapter check failed\n');
    process.exitCode = 1;
}
