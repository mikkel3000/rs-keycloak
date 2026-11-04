-- Realm roles get descriptions and composites; every realm has the reference
-- default roles, and every user holds the realm's default role.
ALTER TABLE roles ADD COLUMN description text CHECK (octet_length(description) <= 255);
CREATE TABLE role_composites (
    realm_id text NOT NULL,
    role_id text NOT NULL,
    child_role_id text NOT NULL,
    PRIMARY KEY (realm_id, role_id, child_role_id),
    FOREIGN KEY (realm_id, role_id) REFERENCES roles(realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, child_role_id) REFERENCES roles(realm_id, id) ON DELETE CASCADE
);
ALTER TABLE realms ADD COLUMN default_role_id text;
ALTER TABLE realms ADD CONSTRAINT realms_default_role FOREIGN KEY (id, default_role_id) REFERENCES roles(realm_id, id) DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION rs_create_default_roles() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    default_role text := gen_random_uuid()::text;
BEGIN
    INSERT INTO roles (realm_id, id, name, description) VALUES
        (NEW.id, gen_random_uuid()::text, 'offline_access', '${role_offline-access}'),
        (NEW.id, gen_random_uuid()::text, 'uma_authorization', '${role_uma_authorization}'),
        (NEW.id, default_role, 'default-roles-' || lower(NEW.name), '${role_default-roles}')
    ON CONFLICT DO NOTHING;
    INSERT INTO role_composites (realm_id, role_id, child_role_id)
        SELECT NEW.id, default_role, r.id FROM roles r
        WHERE r.realm_id = NEW.id AND r.name IN ('offline_access', 'uma_authorization');
    UPDATE realms SET default_role_id = default_role WHERE id = NEW.id;
    RETURN NULL;
END
$$;
CREATE TRIGGER rs_realm_default_roles AFTER INSERT ON realms FOR EACH ROW EXECUTE FUNCTION rs_create_default_roles();

CREATE FUNCTION rs_grant_default_role() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO user_role_grants (realm_id, user_id, role_id)
        SELECT r.id, NEW.id, r.default_role_id FROM realms r
        WHERE r.id = NEW.realm_id AND r.default_role_id IS NOT NULL
    ON CONFLICT DO NOTHING;
    RETURN NULL;
END
$$;
CREATE TRIGGER rs_user_default_role AFTER INSERT ON users FOR EACH ROW EXECUTE FUNCTION rs_grant_default_role();

-- Existing realms and users receive the same defaults.
DO $$
DECLARE
    realm record;
    default_role text;
BEGIN
    FOR realm IN SELECT id, name FROM realms WHERE default_role_id IS NULL LOOP
        default_role := gen_random_uuid()::text;
        INSERT INTO roles (realm_id, id, name, description) VALUES
            (realm.id, gen_random_uuid()::text, 'offline_access', '${role_offline-access}'),
            (realm.id, gen_random_uuid()::text, 'uma_authorization', '${role_uma_authorization}'),
            (realm.id, default_role, 'default-roles-' || lower(realm.name), '${role_default-roles}');
        INSERT INTO role_composites (realm_id, role_id, child_role_id)
            SELECT realm.id, default_role, r.id FROM roles r
            WHERE r.realm_id = realm.id AND r.name IN ('offline_access', 'uma_authorization');
        UPDATE realms SET default_role_id = default_role WHERE id = realm.id;
        INSERT INTO user_role_grants (realm_id, user_id, role_id)
            SELECT realm.id, u.id, default_role FROM users u WHERE u.realm_id = realm.id;
    END LOOP;
END
$$;
