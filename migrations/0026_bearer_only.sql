-- Bearer-only clients only verify tokens: they may authenticate to
-- introspection but never start a login or obtain tokens. Confidential
-- bearer-only clients may have no secret, as the reference's broker and
-- realm-management built-ins do; such clients cannot authenticate at all.
ALTER TABLE clients ADD COLUMN bearer_only boolean NOT NULL DEFAULT false;
ALTER TABLE clients DROP CONSTRAINT clients_secret_type;
ALTER TABLE clients ADD CONSTRAINT clients_secret_type CHECK (
    (secret_sealed IS NULL) = (secret_key_id IS NULL) AND (
        (public_client AND secret_phc IS NULL AND secret_sealed IS NULL) OR
        (NOT public_client AND secret_phc IS NOT NULL AND octet_length(secret_phc) BETWEEN 1 AND 4096 AND secret_sealed IS NULL) OR
        (NOT public_client AND secret_phc IS NULL AND secret_sealed IS NOT NULL) OR
        (NOT public_client AND bearer_only AND secret_phc IS NULL AND secret_sealed IS NULL)
    )
);

-- Adds the bearer-only broker and realm-management clients with their roles
-- and the public security-admin-console. realm-admin includes every other
-- realm-management role; view-users includes query-users and query-groups,
-- and view-clients includes query-clients.
CREATE FUNCTION rs_create_management_clients(p_realm text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    management text;
    broker text;
    role_name text;
BEGIN
    INSERT INTO clients (realm_id, id, client_id, public_client, bearer_only)
    VALUES (p_realm, gen_random_uuid()::text, 'broker', false, true),
           (p_realm, gen_random_uuid()::text, 'realm-management', false, true)
    ON CONFLICT DO NOTHING;
    INSERT INTO clients (realm_id, id, client_id, public_client, standard_flow_enabled)
    VALUES (p_realm, gen_random_uuid()::text, 'security-admin-console', true, false)
    ON CONFLICT DO NOTHING;
    SELECT id INTO broker FROM clients WHERE realm_id = p_realm AND client_id = 'broker';
    SELECT id INTO management FROM clients WHERE realm_id = p_realm AND client_id = 'realm-management';
    INSERT INTO roles (realm_id, id, name, client_id, description)
    VALUES (p_realm, gen_random_uuid()::text, 'read-token', broker, '${role_read-token}')
    ON CONFLICT DO NOTHING;
    FOREACH role_name IN ARRAY ARRAY['create-client', 'impersonation', 'manage-authorization', 'manage-clients', 'manage-events', 'manage-identity-providers', 'manage-organizations', 'manage-realm', 'manage-users', 'query-clients', 'query-groups', 'query-organizations', 'query-realms', 'query-users', 'realm-admin', 'view-authorization', 'view-clients', 'view-events', 'view-identity-providers', 'view-organizations', 'view-realm', 'view-users'] LOOP
        INSERT INTO roles (realm_id, id, name, client_id, description)
        VALUES (p_realm, gen_random_uuid()::text, role_name, management, '${role_' || role_name || '}')
        ON CONFLICT DO NOTHING;
    END LOOP;
    INSERT INTO role_composites (realm_id, role_id, child_role_id)
        SELECT p_realm, parent.id, child.id FROM roles parent JOIN roles child ON child.realm_id = parent.realm_id AND child.client_id = parent.client_id
        WHERE parent.realm_id = p_realm AND parent.client_id = management AND (
            (parent.name = 'realm-admin' AND child.name <> 'realm-admin') OR
            (parent.name = 'view-users' AND child.name IN ('query-users', 'query-groups')) OR
            (parent.name = 'view-clients' AND child.name = 'query-clients'))
    ON CONFLICT DO NOTHING;
END
$$;

CREATE FUNCTION rs_realm_management_clients() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM rs_create_management_clients(NEW.id);
    RETURN NULL;
END
$$;
CREATE TRIGGER rs_realm_management_clients AFTER INSERT ON realms FOR EACH ROW EXECUTE FUNCTION rs_realm_management_clients();

DO $$
DECLARE
    realm record;
BEGIN
    FOR realm IN SELECT id FROM realms LOOP
        PERFORM rs_create_management_clients(realm.id);
    END LOOP;
END
$$;
