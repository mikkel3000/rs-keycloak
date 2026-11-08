-- A browser logout waiting for the user to confirm it, as the reference
-- keeps it in a logout authentication session: the validated redirect and
-- state, the client's ui_locales, the kc_locale pick, and the session an
-- ID token hint named. Bound to the browser by a CSRF cookie digest.
CREATE TABLE logout_requests (
    id text PRIMARY KEY CHECK (octet_length(id) = 64),
    csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash) = 32),
    realm_id text NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    redirect_uri text CHECK (octet_length(redirect_uri) <= 2048),
    state text CHECK (octet_length(state) <= 2048),
    ui_locales text CHECK (octet_length(ui_locales) <= 2048),
    requested_locale text CHECK (octet_length(requested_locale) BETWEEN 1 AND 255),
    hint_session_id text CHECK (octet_length(hint_session_id) <= 255),
    hint_user_id text CHECK (octet_length(hint_user_id) <= 255),
    expires_at timestamptz NOT NULL
);
CREATE INDEX logout_requests_expiry ON logout_requests (expires_at);
