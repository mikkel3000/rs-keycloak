-- Core user profile fields; emails are unique per realm, compared lowercased.
ALTER TABLE users ADD COLUMN email text CHECK (octet_length(email) BETWEEN 1 AND 255);
ALTER TABLE users ADD COLUMN email_normalized text COLLATE "C" CHECK (octet_length(email_normalized) BETWEEN 1 AND 255);
ALTER TABLE users ADD CONSTRAINT users_email_normalized_present CHECK ((email IS NULL) = (email_normalized IS NULL));
ALTER TABLE users ADD COLUMN email_verified boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN first_name text CHECK (octet_length(first_name) BETWEEN 1 AND 255);
ALTER TABLE users ADD COLUMN last_name text CHECK (octet_length(last_name) BETWEEN 1 AND 255);
ALTER TABLE users ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp();
CREATE UNIQUE INDEX users_email_unique ON users (realm_id, email_normalized) WHERE email_normalized IS NOT NULL;
