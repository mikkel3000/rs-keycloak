-- Email verification: realms may require it, VERIFY_EMAIL joins the required
-- actions, and one function prepares a new session's login steps so every
-- session-creating path adds the action the same way.
ALTER TABLE realms ADD COLUMN verify_email boolean NOT NULL DEFAULT false;
ALTER TABLE users DROP CONSTRAINT users_required_actions_check;
ALTER TABLE users ADD CONSTRAINT users_required_actions_check CHECK (required_actions <@ ARRAY['CONFIGURE_TOTP', 'UPDATE_PASSWORD', 'VERIFY_EMAIL']::text[]);

CREATE FUNCTION rs_prepare_login_steps(p_realm text, p_user text) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    UPDATE users u SET required_actions = array_append(u.required_actions, 'VERIFY_EMAIL')
    FROM realms r
    WHERE r.id = u.realm_id AND u.realm_id = p_realm AND u.id = p_user
      AND r.verify_email AND u.email IS NOT NULL AND NOT u.email_verified
      AND NOT ('VERIFY_EMAIL' = ANY(u.required_actions));
    RETURN EXISTS (SELECT 1 FROM credentials c WHERE c.realm_id = p_realm AND c.user_id = p_user AND c.credential_type = 'otp')
        OR EXISTS (SELECT 1 FROM users u WHERE u.realm_id = p_realm AND u.id = p_user AND cardinality(u.required_actions) > 0);
END
$$;
