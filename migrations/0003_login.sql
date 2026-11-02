ALTER TABLE credentials ADD COLUMN revision bigint NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX credentials_one_password_per_user ON credentials (realm_id, user_id) WHERE credential_type = 'password';
CREATE TABLE login_policy (
    realm_id text PRIMARY KEY REFERENCES realms(id) ON DELETE CASCADE,
    max_failures integer NOT NULL DEFAULT 5 CHECK (max_failures BETWEEN 1 AND 100),
    lock_seconds integer NOT NULL DEFAULT 60 CHECK (lock_seconds BETWEEN 1 AND 86400)
);
CREATE TABLE login_lockouts (
    realm_id text NOT NULL,
    user_id text NOT NULL,
    failures integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
    locked_until timestamptz,
    PRIMARY KEY (realm_id, user_id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users(realm_id, id) ON DELETE CASCADE
);
CREATE TABLE login_challenges (
    id text PRIMARY KEY,
    realm_id text NOT NULL,
    user_id text NOT NULL,
    client_id text NOT NULL,
    credential_id text NOT NULL,
    user_revision bigint NOT NULL,
    credential_revision bigint NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    FOREIGN KEY (realm_id, user_id) REFERENCES users(realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, client_id) REFERENCES clients(realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, credential_id) REFERENCES credentials(realm_id, id) ON DELETE CASCADE
);
CREATE INDEX login_challenges_user ON login_challenges (realm_id, user_id, expires_at) WHERE consumed_at IS NULL;
CREATE INDEX login_challenges_expiry ON login_challenges (expires_at);

CREATE FUNCTION rs_bump_user_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.revision := OLD.revision + 1;
    RETURN NEW;
END
$$;
CREATE TRIGGER rs_user_revision BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION rs_bump_user_revision();
CREATE FUNCTION rs_bump_credential_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.revision := OLD.revision + 1;
    RETURN NEW;
END
$$;
CREATE TRIGGER rs_credential_revision BEFORE UPDATE ON credentials FOR EACH ROW EXECUTE FUNCTION rs_bump_credential_revision();
