-- rememberMe, as the reference's realm settings: the login form offers it,
-- and a remembered session lives for the larger of the idle timeout and its
-- remember-me value; 0 keeps the normal lifetimes.
ALTER TABLE realms ADD COLUMN remember_me boolean NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN sso_session_idle_timeout_remember_me integer NOT NULL DEFAULT 0;
ALTER TABLE realms ADD COLUMN sso_session_max_lifespan_remember_me integer NOT NULL DEFAULT 0;
ALTER TABLE user_sessions ADD COLUMN remember_me boolean NOT NULL DEFAULT false;
