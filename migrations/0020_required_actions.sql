-- UPDATE_PASSWORD joins CONFIGURE_TOTP as a required action. A session stays
-- pending while any login step remains, so the flag is renamed to say so, and
-- a verified OTP code is recorded separately from the remaining actions.
ALTER TABLE users DROP CONSTRAINT users_required_actions_check;
ALTER TABLE users ADD CONSTRAINT users_required_actions_check CHECK (required_actions <@ ARRAY['CONFIGURE_TOTP', 'UPDATE_PASSWORD']::text[]);
ALTER TABLE user_sessions RENAME COLUMN mfa_pending TO steps_pending;
ALTER TABLE user_sessions ADD COLUMN otp_verified boolean NOT NULL DEFAULT false;
