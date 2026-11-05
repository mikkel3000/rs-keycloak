-- Groups hold roles; members gain them, and the roles of every ancestor
-- group, as effective roles.
CREATE TABLE group_role_grants (
    realm_id text NOT NULL,
    group_id text NOT NULL,
    role_id text NOT NULL,
    PRIMARY KEY (realm_id, group_id, role_id),
    FOREIGN KEY (realm_id, group_id) REFERENCES groups(realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, role_id) REFERENCES roles(realm_id, id) ON DELETE CASCADE
);
CREATE INDEX group_role_grants_role ON group_role_grants (realm_id, role_id);
