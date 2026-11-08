-- Email login and duplicate emails, as the reference's realm settings: users
-- may sign in with their email unless the realm turns it off, and a realm
-- that allows duplicate emails has it off when the setting is given.
ALTER TABLE realms ADD COLUMN login_with_email_allowed boolean NOT NULL DEFAULT true;
ALTER TABLE realms ADD COLUMN duplicate_emails_allowed boolean NOT NULL DEFAULT false;
-- An email set while the realm allowed duplicates is not unique, as the
-- reference gives it a random EMAIL_CONSTRAINT; others stay unique.
ALTER TABLE users ADD COLUMN email_unique boolean NOT NULL DEFAULT true;
DROP INDEX users_email_unique;
CREATE UNIQUE INDEX users_email_unique ON users (realm_id, email_normalized) WHERE email_normalized IS NOT NULL AND email_unique;
CREATE INDEX users_email_lookup ON users (realm_id, email_normalized) WHERE email_normalized IS NOT NULL;
