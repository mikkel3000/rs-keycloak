CREATE TABLE refresh_families (
    id text PRIMARY KEY,
    realm_id text NOT NULL,
    client_id text NOT NULL,
    user_session_id text NOT NULL,
    scope text NOT NULL CHECK (octet_length(scope) BETWEEN 1 AND 2048),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    FOREIGN KEY (realm_id, client_id) REFERENCES clients(realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, user_session_id) REFERENCES user_sessions(realm_id, id) ON DELETE CASCADE
);
CREATE INDEX refresh_families_expiry ON refresh_families(expires_at);
CREATE TABLE refresh_tokens (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    family_id text NOT NULL REFERENCES refresh_families(id) ON DELETE CASCADE,
    generation bigint NOT NULL CHECK (generation >= 0),
    consumed_at timestamptz,
    UNIQUE (family_id, generation)
);
