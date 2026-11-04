-- OAuth consent: clients may require it, users grant it once per client, and
-- an authorization request remembers prompt=consent and the session that is
-- waiting for the user's answer.
ALTER TABLE clients ADD COLUMN consent_required boolean NOT NULL DEFAULT false;
CREATE TABLE user_consents (
    realm_id text NOT NULL,
    user_id text NOT NULL,
    client_id text NOT NULL,
    scope text NOT NULL CHECK (octet_length(scope) <= 2048),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (realm_id, user_id, client_id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users(realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, client_id) REFERENCES clients(realm_id, id) ON DELETE CASCADE
);
ALTER TABLE authorization_requests ADD COLUMN prompt_consent boolean NOT NULL DEFAULT false;
ALTER TABLE authorization_requests ADD COLUMN pending_session_id text;
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_pending_session FOREIGN KEY (realm_id, pending_session_id) REFERENCES user_sessions(realm_id, id) ON DELETE CASCADE;
