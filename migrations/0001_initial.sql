CREATE TABLE realms (
    id text PRIMARY KEY,
    name text NOT NULL UNIQUE,
    enabled boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 0
);
CREATE TABLE clients (
    realm_id text NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    id text NOT NULL,
    client_id text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    PRIMARY KEY (realm_id, id),
    UNIQUE (realm_id, client_id)
);
CREATE TABLE users (
    realm_id text NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    id text NOT NULL,
    username text NOT NULL,
    username_normalized text COLLATE "C" NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (realm_id, id),
    UNIQUE (realm_id, username_normalized)
);
CREATE TABLE credentials (
    realm_id text NOT NULL,
    id text NOT NULL,
    user_id text NOT NULL,
    credential_type text NOT NULL,
    secret_data bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (realm_id, id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users(realm_id, id) ON DELETE CASCADE
);
CREATE TABLE user_sessions (
    realm_id text NOT NULL,
    id text NOT NULL,
    user_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (realm_id, id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users(realm_id, id) ON DELETE CASCADE
);
CREATE INDEX user_sessions_expires_at ON user_sessions (expires_at);
CREATE TABLE client_sessions (
    realm_id text NOT NULL,
    id text NOT NULL,
    user_session_id text NOT NULL,
    client_id text NOT NULL,
    PRIMARY KEY (realm_id, id),
    FOREIGN KEY (realm_id, user_session_id) REFERENCES user_sessions(realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, client_id) REFERENCES clients(realm_id, id) ON DELETE CASCADE
);
