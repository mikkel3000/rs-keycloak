-- Forgot-password: realms opt in, and an emailed token remembers the login
-- request it was sent from so the same browser can continue that login.
ALTER TABLE realms ADD COLUMN reset_password_allowed boolean NOT NULL DEFAULT false;
ALTER TABLE action_tokens ADD COLUMN authorization_request_id text REFERENCES authorization_requests(id) ON DELETE SET NULL;
