-- Offline refresh families outlive their login session: logging out or an
-- admin sign-out leaves them, while revocation, consent removal and their
-- own 30-day expiry end them.
ALTER TABLE refresh_families ADD COLUMN offline boolean NOT NULL DEFAULT false;
CREATE INDEX refresh_families_offline ON refresh_families (realm_id, client_id) WHERE offline;
