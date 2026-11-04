-- TOTP: users may carry the CONFIGURE_TOTP required action, OTP credentials
-- keep a sealed seed, a label and the last accepted step, and a session stays
-- pending until its second factor passes.
ALTER TABLE users ADD COLUMN required_actions text[] NOT NULL DEFAULT '{}' CHECK (required_actions <@ ARRAY['CONFIGURE_TOTP']::text[]);
ALTER TABLE credentials ADD COLUMN user_label text CHECK (octet_length(user_label) <= 255);
ALTER TABLE credentials ADD COLUMN secret_key_id text CHECK (octet_length(secret_key_id) BETWEEN 1 AND 64);
ALTER TABLE credentials ADD COLUMN otp_last_step bigint;
ALTER TABLE credentials ADD CONSTRAINT credentials_otp_sealed CHECK (credential_type <> 'otp' OR secret_key_id IS NOT NULL);
CREATE UNIQUE INDEX credentials_one_otp_per_user ON credentials (realm_id, user_id) WHERE credential_type = 'otp';
ALTER TABLE user_sessions ADD COLUMN mfa_pending boolean NOT NULL DEFAULT false;
