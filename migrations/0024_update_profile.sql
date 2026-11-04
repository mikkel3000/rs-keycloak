-- UPDATE_PROFILE joins the supported required actions.
ALTER TABLE users DROP CONSTRAINT users_required_actions_check;
ALTER TABLE users ADD CONSTRAINT users_required_actions_check CHECK (required_actions <@ ARRAY['CONFIGURE_TOTP', 'UPDATE_PASSWORD', 'UPDATE_PROFILE', 'VERIFY_EMAIL']::text[]);
