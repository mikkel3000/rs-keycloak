-- The realm OTP policy, as the reference's OTPPolicy: stored as given,
-- since the reference checks none of it; the algorithm may be null.
ALTER TABLE realms ADD COLUMN otp_policy_type text NOT NULL DEFAULT 'totp' CHECK (length(otp_policy_type) <= 255);
ALTER TABLE realms ADD COLUMN otp_policy_algorithm text DEFAULT 'HmacSHA1' CHECK (length(otp_policy_algorithm) <= 255);
ALTER TABLE realms ADD COLUMN otp_policy_digits integer NOT NULL DEFAULT 6;
ALTER TABLE realms ADD COLUMN otp_policy_period integer NOT NULL DEFAULT 30;
ALTER TABLE realms ADD COLUMN otp_policy_look_ahead integer NOT NULL DEFAULT 1;
ALTER TABLE realms ADD COLUMN otp_policy_initial_counter integer NOT NULL DEFAULT 0;
ALTER TABLE realms ADD COLUMN otp_policy_code_reusable boolean NOT NULL DEFAULT false;

-- An OTP credential keeps the policy it was made with, as OTPCredentialData,
-- and its HOTP counter. Steps of accepted TOTP codes are kept while they
-- can still match, so each code is accepted once, as the reference's
-- single-use store does; this replaces the last accepted step.
ALTER TABLE credentials ADD COLUMN otp_type text;
ALTER TABLE credentials ADD COLUMN otp_algorithm text;
ALTER TABLE credentials ADD COLUMN otp_digits integer;
ALTER TABLE credentials ADD COLUMN otp_period integer;
ALTER TABLE credentials ADD COLUMN otp_counter bigint;
ALTER TABLE credentials ADD COLUMN otp_used_steps bigint[] NOT NULL DEFAULT '{}';
UPDATE credentials SET otp_type = 'totp', otp_algorithm = 'HmacSHA1', otp_digits = 6, otp_period = 30, otp_counter = 0,
    otp_used_steps = CASE WHEN otp_last_step IS NULL THEN '{}' ELSE ARRAY[otp_last_step] END
    WHERE credential_type = 'otp';
ALTER TABLE credentials DROP COLUMN otp_last_step;
