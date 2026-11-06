-- Realms may have a display name, and set the lifetime of the access and
-- ID tokens they issue; only positive lifetimes are stored.
ALTER TABLE realms ADD COLUMN display_name text CHECK (octet_length(display_name) <= 255);
ALTER TABLE realms ADD COLUMN access_token_lifespan integer NOT NULL DEFAULT 300 CHECK (access_token_lifespan > 0);
