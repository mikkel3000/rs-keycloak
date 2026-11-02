CREATE TABLE roles (
    realm_id text NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    id text NOT NULL,
    name text NOT NULL,
    PRIMARY KEY (realm_id, id),
    UNIQUE (realm_id, name)
);
CREATE TABLE user_role_grants (
    realm_id text NOT NULL,
    user_id text NOT NULL,
    role_id text NOT NULL,
    PRIMARY KEY (realm_id, user_id, role_id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users(realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, role_id) REFERENCES roles(realm_id, id) ON DELETE CASCADE
);
CREATE TABLE bootstrap_admin (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    realm_id text NOT NULL,
    user_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (realm_id, user_id) REFERENCES users(realm_id, id)
);
CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    realm_id text NOT NULL REFERENCES realms(id),
    actor_user_id text NOT NULL,
    event_type text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (realm_id, actor_user_id) REFERENCES users(realm_id, id)
);
