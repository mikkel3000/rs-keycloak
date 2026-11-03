CREATE TABLE revoked_access_tokens (
    realm_id text NOT NULL,
    jti_hash bytea NOT NULL CHECK (octet_length(jti_hash) = 32),
    session_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (realm_id, jti_hash),
    FOREIGN KEY (realm_id, session_id) REFERENCES user_sessions(realm_id, id) ON DELETE CASCADE
);
CREATE INDEX revoked_access_tokens_expiry ON revoked_access_tokens(expires_at);
