-- Brute-force detection, as the reference's realm settings and
-- DefaultBruteForceProtector: off by default, so a realm that does not turn
-- it on never locks a user. This replaces the fixed lockout of migration 3.
ALTER TABLE realms ADD COLUMN brute_force_protected boolean NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN permanent_lockout boolean NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN max_temporary_lockouts integer NOT NULL DEFAULT 0;
ALTER TABLE realms ADD COLUMN brute_force_strategy text NOT NULL DEFAULT 'MULTIPLE' CHECK (brute_force_strategy IN ('MULTIPLE', 'LINEAR'));
ALTER TABLE realms ADD COLUMN max_failure_wait_seconds integer NOT NULL DEFAULT 900;
ALTER TABLE realms ADD COLUMN minimum_quick_login_wait_seconds integer NOT NULL DEFAULT 60;
ALTER TABLE realms ADD COLUMN wait_increment_seconds integer NOT NULL DEFAULT 60;
ALTER TABLE realms ADD COLUMN quick_login_check_milli_seconds bigint NOT NULL DEFAULT 1000;
ALTER TABLE realms ADD COLUMN max_delta_time_seconds integer NOT NULL DEFAULT 43200;
ALTER TABLE realms ADD COLUMN failure_factor integer NOT NULL DEFAULT 30;

-- A user's login failures, as the reference's UserLoginFailureModel; a row
-- exists only while failures are counted.
DROP TABLE login_policy;
DROP TABLE login_lockouts;
CREATE TABLE login_failures (
    realm_id text NOT NULL,
    user_id text NOT NULL,
    num_failures integer NOT NULL DEFAULT 0,
    num_temporary_lockouts integer NOT NULL DEFAULT 0,
    last_failure bigint NOT NULL DEFAULT 0,
    last_ip_failure text,
    failed_login_not_before bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (realm_id, user_id),
    FOREIGN KEY (realm_id, user_id) REFERENCES users(realm_id, id) ON DELETE CASCADE
);

-- Why a user was disabled; permanent lockout sets it, as the reference's
-- disabledReason attribute.
ALTER TABLE users ADD COLUMN disabled_reason text CHECK (length(disabled_reason) <= 255);
