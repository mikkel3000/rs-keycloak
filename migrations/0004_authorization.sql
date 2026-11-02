ALTER TABLE user_sessions ADD COLUMN revoked_at timestamptz;
ALTER TABLE clients ADD COLUMN public_client boolean NOT NULL DEFAULT true;
CREATE TABLE client_redirect_uris (
    realm_id text NOT NULL,
    client_id text NOT NULL,
    redirect_uri text NOT NULL CHECK (octet_length(redirect_uri) BETWEEN 1 AND 2048),
    PRIMARY KEY (realm_id, client_id, redirect_uri),
    FOREIGN KEY (realm_id, client_id) REFERENCES clients(realm_id, id) ON DELETE CASCADE
);
CREATE TABLE authorization_requests (
    id text PRIMARY KEY,
    csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash) = 32),
    realm_id text NOT NULL,
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    pkce_s256 bytea NOT NULL CHECK (octet_length(pkce_s256) = 32),
    state text CHECK (octet_length(state) <= 2048),
    scope text NOT NULL CHECK (octet_length(scope) BETWEEN 1 AND 2048),
    nonce text CHECK (octet_length(nonce) <= 2048),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    FOREIGN KEY (realm_id, client_id, redirect_uri) REFERENCES client_redirect_uris(realm_id, client_id, redirect_uri) ON DELETE CASCADE
);
CREATE INDEX authorization_requests_expiry ON authorization_requests(expires_at);
CREATE TABLE authorization_codes (
    code_hash bytea PRIMARY KEY CHECK (octet_length(code_hash) = 32),
    realm_id text NOT NULL,
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    user_session_id text NOT NULL,
    pkce_s256 bytea NOT NULL CHECK (octet_length(pkce_s256) = 32),
    scope text NOT NULL CHECK (octet_length(scope) BETWEEN 1 AND 2048),
    nonce text CHECK (octet_length(nonce) <= 2048),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    FOREIGN KEY (realm_id, client_id, redirect_uri) REFERENCES client_redirect_uris(realm_id, client_id, redirect_uri) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, user_session_id) REFERENCES user_sessions(realm_id, id) ON DELETE CASCADE
);
CREATE INDEX authorization_codes_expiry ON authorization_codes(expires_at);
