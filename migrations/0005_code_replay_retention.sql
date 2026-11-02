ALTER TABLE authorization_codes ADD COLUMN replay_until timestamptz;
UPDATE authorization_codes a SET replay_until = us.expires_at
FROM user_sessions us WHERE us.realm_id = a.realm_id AND us.id = a.user_session_id;
ALTER TABLE authorization_codes ALTER COLUMN replay_until SET NOT NULL;
CREATE INDEX authorization_codes_replay_until ON authorization_codes (replay_until);
