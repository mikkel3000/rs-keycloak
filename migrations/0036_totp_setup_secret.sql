-- The TOTP setup page keeps its key for the rest of a login, as the
-- reference keeps it in the authentication session's TOTP_SECRET_KEY note.
-- Sealed with the server's secret key, bound to the request.
ALTER TABLE authorization_requests ADD COLUMN totp_setup_secret bytea CHECK (octet_length(totp_setup_secret) <= 256);
