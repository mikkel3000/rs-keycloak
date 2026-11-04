-- Browser SSO: the KEYCLOAK_IDENTITY cookie carries a random token whose
-- digest identifies the user session; each client joins a session once.
ALTER TABLE user_sessions ADD COLUMN sso_token_hash bytea CHECK (octet_length(sso_token_hash) = 32);
CREATE UNIQUE INDEX user_sessions_sso_token ON user_sessions (sso_token_hash) WHERE sso_token_hash IS NOT NULL;
CREATE UNIQUE INDEX client_sessions_one_per_client ON client_sessions (realm_id, user_session_id, client_id);
