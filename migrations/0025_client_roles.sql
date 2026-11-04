-- Roles may belong to a client. Names are unique per container: realm roles
-- among realm roles, client roles within their client.
ALTER TABLE roles ADD COLUMN client_id text;
ALTER TABLE roles ADD CONSTRAINT roles_client FOREIGN KEY (realm_id, client_id) REFERENCES clients(realm_id, id) ON DELETE CASCADE;
ALTER TABLE roles DROP CONSTRAINT roles_realm_id_name_key;
CREATE UNIQUE INDEX roles_realm_name ON roles (realm_id, name) WHERE client_id IS NULL;
CREATE UNIQUE INDEX roles_client_name ON roles (realm_id, client_id, name) WHERE client_id IS NOT NULL;

-- Every realm has Keycloak's public built-in clients, and the account client
-- carries its roles; the default role includes view-profile and
-- manage-account, which includes manage-account-links.
CREATE FUNCTION rs_create_builtin_clients(p_realm text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    account text := gen_random_uuid()::text;
    role_name text;
BEGIN
    INSERT INTO clients (realm_id, id, client_id, public_client, standard_flow_enabled)
    VALUES (p_realm, account, 'account', true, false),
           (p_realm, gen_random_uuid()::text, 'account-console', true, false),
           (p_realm, gen_random_uuid()::text, 'admin-cli', true, false)
    ON CONFLICT DO NOTHING;
    SELECT id INTO account FROM clients WHERE realm_id = p_realm AND client_id = 'account';
    FOREACH role_name IN ARRAY ARRAY['delete-account', 'manage-account', 'manage-account-links', 'manage-consent', 'view-applications', 'view-consent', 'view-groups', 'view-profile'] LOOP
        INSERT INTO roles (realm_id, id, name, client_id, description)
        VALUES (p_realm, gen_random_uuid()::text, role_name, account, '${role_' || replace(role_name, '-', '_') || '}')
        ON CONFLICT DO NOTHING;
    END LOOP;
    INSERT INTO role_composites (realm_id, role_id, child_role_id)
        SELECT p_realm, parent.id, child.id FROM roles parent JOIN roles child ON child.realm_id = parent.realm_id AND child.client_id = parent.client_id
        WHERE parent.realm_id = p_realm AND parent.client_id = account AND parent.name = 'manage-account' AND child.name = 'manage-account-links'
    ON CONFLICT DO NOTHING;
    INSERT INTO role_composites (realm_id, role_id, child_role_id)
        SELECT p_realm, r.default_role_id, child.id FROM realms r JOIN roles child ON child.realm_id = r.id AND child.client_id = account
        WHERE r.id = p_realm AND r.default_role_id IS NOT NULL AND child.name IN ('view-profile', 'manage-account')
    ON CONFLICT DO NOTHING;
END
$$;

CREATE FUNCTION rs_realm_builtin_clients() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM rs_create_builtin_clients(NEW.id);
    RETURN NULL;
END
$$;
-- Named to run after rs_realm_default_roles, whose default role it extends.
CREATE TRIGGER rs_realm_default_roles_then_clients AFTER INSERT ON realms FOR EACH ROW EXECUTE FUNCTION rs_realm_builtin_clients();

DO $$
DECLARE
    realm record;
BEGIN
    FOR realm IN SELECT id FROM realms LOOP
        PERFORM rs_create_builtin_clients(realm.id);
    END LOOP;
END
$$;
