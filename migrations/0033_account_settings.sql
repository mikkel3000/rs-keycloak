-- Realms may enable internationalization with supported and default
-- locales, let users edit their username, and use the email as username.
-- Locales are stored even while internationalization is off, as in the
-- reference; an empty default locale is kept as given.
ALTER TABLE realms ADD COLUMN internationalization_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN supported_locales text[] NOT NULL DEFAULT '{}' CHECK (cardinality(supported_locales) <= 200);
ALTER TABLE realms ADD COLUMN default_locale text CHECK (octet_length(default_locale) <= 255);
ALTER TABLE realms ADD COLUMN edit_username_allowed boolean NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN registration_email_as_username boolean NOT NULL DEFAULT false;

-- Clients may have a display name and a description.
ALTER TABLE clients ADD COLUMN name text CHECK (octet_length(name) <= 255);
ALTER TABLE clients ADD COLUMN description text CHECK (octet_length(description) <= 255);

-- The locale a user chose in the account console.
ALTER TABLE users ADD COLUMN locale text CHECK (octet_length(locale) BETWEEN 1 AND 255);

-- The reference names each built-in client by a message key.
CREATE FUNCTION rs_set_builtin_client_names(p_realm text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    UPDATE clients SET name = '${client_' || client_id || '}'
        WHERE realm_id = p_realm AND name IS NULL
        AND client_id IN ('account', 'account-console', 'admin-cli', 'broker', 'realm-management', 'security-admin-console');
END
$$;

CREATE FUNCTION rs_realm_builtin_client_names() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM rs_set_builtin_client_names(NEW.id);
    RETURN NULL;
END
$$;
-- Named to run after the triggers that create the built-in clients.
CREATE TRIGGER rs_realm_management_clients_then_urls_then_names AFTER INSERT ON realms FOR EACH ROW EXECUTE FUNCTION rs_realm_builtin_client_names();

DO $$
DECLARE
    realm record;
BEGIN
    FOR realm IN SELECT id FROM realms LOOP
        PERFORM rs_set_builtin_client_names(realm.id);
    END LOOP;
END
$$;
