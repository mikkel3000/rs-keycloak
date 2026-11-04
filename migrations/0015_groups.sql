-- Groups form a tree per realm; names are unique among top-level groups and
-- among siblings, and deleting a group removes its subgroups.
CREATE TABLE groups (
    realm_id text NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    id text NOT NULL,
    parent_id text,
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 255 AND position('/' in name) = 0),
    PRIMARY KEY (realm_id, id),
    FOREIGN KEY (realm_id, parent_id) REFERENCES groups(realm_id, id) ON DELETE CASCADE,
    CHECK (parent_id IS NULL OR parent_id <> id)
);
CREATE UNIQUE INDEX groups_top_level_name ON groups (realm_id, name) WHERE parent_id IS NULL;
CREATE UNIQUE INDEX groups_sibling_name ON groups (realm_id, parent_id, name) WHERE parent_id IS NOT NULL;
CREATE TABLE group_members (
    realm_id text NOT NULL,
    group_id text NOT NULL,
    user_id text NOT NULL,
    PRIMARY KEY (realm_id, group_id, user_id),
    FOREIGN KEY (realm_id, group_id) REFERENCES groups(realm_id, id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id, user_id) REFERENCES users(realm_id, id) ON DELETE CASCADE
);
CREATE INDEX group_members_user ON group_members (realm_id, user_id);

-- Slash-joined names from the root, as in the reference group path.
CREATE FUNCTION rs_group_path(realm text, group_id text) RETURNS text LANGUAGE sql STABLE AS $$
    WITH RECURSIVE ancestors(id, parent_id, name, depth) AS (
        SELECT id, parent_id, name, 0 FROM groups WHERE realm_id = realm AND id = group_id
        UNION ALL
        SELECT g.id, g.parent_id, g.name, a.depth + 1
        FROM groups g JOIN ancestors a ON g.realm_id = realm AND g.id = a.parent_id
        WHERE a.depth < 64
    )
    SELECT '/' || string_agg(name, '/' ORDER BY depth DESC) FROM ancestors
$$;
