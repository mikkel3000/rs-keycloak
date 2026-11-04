-- Realm SMTP settings and single-use action tokens sent by email.
ALTER TABLE realms ADD COLUMN smtp_host text CHECK (octet_length(smtp_host) BETWEEN 1 AND 255);
ALTER TABLE realms ADD COLUMN smtp_port integer CHECK (smtp_port BETWEEN 1 AND 65535);
ALTER TABLE realms ADD COLUMN smtp_from text CHECK (octet_length(smtp_from) BETWEEN 1 AND 255);
ALTER TABLE realms ADD COLUMN smtp_from_display_name text CHECK (octet_length(smtp_from_display_name) <= 255);
ALTER TABLE realms ADD COLUMN smtp_starttls boolean NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN smtp_ssl boolean NOT NULL DEFAULT false;
CREATE TABLE action_tokens (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    realm_id text NOT NULL,
    user_id text NOT NULL,
    actions text[] NOT NULL CHECK (cardinality(actions) BETWEEN 1 AND 8),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    FOREIGN KEY (realm_id, user_id) REFERENCES users(realm_id, id) ON DELETE CASCADE
);
CREATE INDEX action_tokens_expiry ON action_tokens (expires_at);
