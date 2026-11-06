-- Realms may disable required actions or make them default for new users.
-- Only changed actions have a row; the rest are enabled and not default.
CREATE TABLE required_action_settings (
    realm_id text NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    alias text NOT NULL CHECK (alias IN ('CONFIGURE_TOTP', 'UPDATE_PASSWORD', 'UPDATE_PROFILE', 'VERIFY_EMAIL')),
    enabled boolean NOT NULL,
    default_action boolean NOT NULL,
    PRIMARY KEY (realm_id, alias)
);

-- The assigned actions a realm has not disabled; login runs only these, and
-- a session waits for steps only while one is left.
CREATE FUNCTION rs_active_required_actions(p_realm text, p_actions text[]) RETURNS text[] LANGUAGE sql STABLE AS $$
    SELECT COALESCE(array_agg(action ORDER BY action), '{}') FROM unnest(p_actions) AS action
    WHERE NOT EXISTS (SELECT 1 FROM required_action_settings s WHERE s.realm_id = p_realm AND s.alias = action AND NOT s.enabled)
$$;

CREATE OR REPLACE FUNCTION rs_prepare_login_steps(p_realm text, p_user text) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    UPDATE users u SET required_actions = array_append(u.required_actions, 'VERIFY_EMAIL')
    FROM realms r
    WHERE r.id = u.realm_id AND u.realm_id = p_realm AND u.id = p_user
      AND r.verify_email AND u.email IS NOT NULL AND NOT u.email_verified
      AND NOT ('VERIFY_EMAIL' = ANY(u.required_actions));
    RETURN EXISTS (SELECT 1 FROM credentials c WHERE c.realm_id = p_realm AND c.user_id = p_user AND c.credential_type = 'otp')
        OR EXISTS (SELECT 1 FROM users u WHERE u.realm_id = p_realm AND u.id = p_user AND cardinality(rs_active_required_actions(u.realm_id, u.required_actions)) > 0);
END
$$;
