-- Clients may have a root URL, against which relative redirect URIs
-- resolve, and a base URL that names their home page. Registered redirect
-- URIs may end in /* to match everything below them.
ALTER TABLE clients ADD COLUMN root_url text CHECK (octet_length(root_url) BETWEEN 1 AND 2048);
ALTER TABLE clients ADD COLUMN base_url text CHECK (octet_length(base_url) BETWEEN 1 AND 2048);

-- Requests and codes keep the URI asked for and the registered URI it
-- matched; removing that registered URI still cancels them.
ALTER TABLE authorization_requests ADD COLUMN registered_redirect text;
UPDATE authorization_requests SET registered_redirect = redirect_uri;
ALTER TABLE authorization_requests ALTER COLUMN registered_redirect SET NOT NULL;
ALTER TABLE authorization_requests DROP CONSTRAINT authorization_requests_realm_id_client_id_redirect_uri_fkey;
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_registered_redirect_fkey FOREIGN KEY (realm_id, client_id, registered_redirect) REFERENCES client_redirect_uris(realm_id, client_id, redirect_uri) ON DELETE CASCADE;
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_redirect_length CHECK (octet_length(redirect_uri) BETWEEN 1 AND 2048);
ALTER TABLE authorization_codes ADD COLUMN registered_redirect text;
UPDATE authorization_codes SET registered_redirect = redirect_uri;
ALTER TABLE authorization_codes ALTER COLUMN registered_redirect SET NOT NULL;
ALTER TABLE authorization_codes DROP CONSTRAINT authorization_codes_realm_id_client_id_redirect_uri_fkey;
ALTER TABLE authorization_codes ADD CONSTRAINT authorization_codes_registered_redirect_fkey FOREIGN KEY (realm_id, client_id, registered_redirect) REFERENCES client_redirect_uris(realm_id, client_id, redirect_uri) ON DELETE CASCADE;

-- The reference's built-in URLs: the account clients under
-- ${authBaseUrl}/realms/{realm}/account/ and the admin console under
-- ${authAdminUrl}/admin/{realm}/console/, each signing in through its path.
CREATE FUNCTION rs_set_builtin_client_urls(p_realm text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    realm_name text;
BEGIN
    SELECT name INTO realm_name FROM realms WHERE id = p_realm;
    UPDATE clients SET root_url = '${authBaseUrl}', base_url = '/realms/' || realm_name || '/account/', standard_flow_enabled = true
        WHERE realm_id = p_realm AND client_id IN ('account', 'account-console') AND root_url IS NULL;
    UPDATE clients SET root_url = '${authAdminUrl}', base_url = '/admin/' || realm_name || '/console/', standard_flow_enabled = true
        WHERE realm_id = p_realm AND client_id = 'security-admin-console' AND root_url IS NULL;
    INSERT INTO client_redirect_uris (realm_id, client_id, redirect_uri)
        SELECT p_realm, id, CASE WHEN client_id = 'security-admin-console' THEN '/admin/' || realm_name || '/console/*' ELSE '/realms/' || realm_name || '/account/*' END
        FROM clients WHERE realm_id = p_realm AND client_id IN ('account', 'account-console', 'security-admin-console')
    ON CONFLICT DO NOTHING;
END
$$;

CREATE FUNCTION rs_realm_builtin_client_urls() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM rs_set_builtin_client_urls(NEW.id);
    RETURN NULL;
END
$$;
-- Named to run after the triggers that create the built-in clients.
CREATE TRIGGER rs_realm_management_clients_then_urls AFTER INSERT ON realms FOR EACH ROW EXECUTE FUNCTION rs_realm_builtin_client_urls();

DO $$
DECLARE
    realm record;
BEGIN
    FOR realm IN SELECT id FROM realms LOOP
        PERFORM rs_set_builtin_client_urls(realm.id);
    END LOOP;
END
$$;
