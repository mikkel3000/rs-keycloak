-- VERIFY_PROFILE, as the reference's VerifyUserProfile: on by default, it
-- stops a login whose user the default user profile finds incomplete (no
-- first name, last name or email) without being assigned to the user.
ALTER TABLE required_action_settings DROP CONSTRAINT required_action_settings_alias_check;
ALTER TABLE required_action_settings ADD CONSTRAINT required_action_settings_alias_check
    CHECK (alias IN ('CONFIGURE_TOTP', 'UPDATE_PASSWORD', 'UPDATE_PROFILE', 'VERIFY_EMAIL', 'VERIFY_PROFILE'));

-- Whether the user must complete their profile at login: the realm has not
-- disabled VERIFY_PROFILE and a required field is missing.
CREATE FUNCTION rs_verify_profile_due(p_realm text, p_user text) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM users u
        WHERE u.realm_id = p_realm AND u.id = p_user
          AND (u.first_name IS NULL OR u.last_name IS NULL OR u.email IS NULL)
          AND NOT EXISTS (SELECT 1 FROM required_action_settings s WHERE s.realm_id = p_realm AND s.alias = 'VERIFY_PROFILE' AND NOT s.enabled)
    )
$$;

CREATE OR REPLACE FUNCTION rs_prepare_login_steps(p_realm text, p_user text) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    UPDATE users u SET required_actions = array_append(u.required_actions, 'VERIFY_EMAIL')
    FROM realms r
    WHERE r.id = u.realm_id AND u.realm_id = p_realm AND u.id = p_user
      AND r.verify_email AND u.email IS NOT NULL AND NOT u.email_verified
      AND NOT ('VERIFY_EMAIL' = ANY(u.required_actions));
    RETURN EXISTS (SELECT 1 FROM credentials c WHERE c.realm_id = p_realm AND c.user_id = p_user AND c.credential_type = 'otp')
        OR EXISTS (SELECT 1 FROM users u WHERE u.realm_id = p_realm AND u.id = p_user AND cardinality(rs_active_required_actions(u.realm_id, u.required_actions)) > 0)
        OR rs_verify_profile_due(p_realm, p_user);
END
$$;
