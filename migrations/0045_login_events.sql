-- Stored login events, as the reference's EVENT_ENTITY: one row per event
-- of a realm with events on, removed with the realm. Times are epoch
-- milliseconds, as the admin API shows them.
CREATE TABLE login_events (
    id text PRIMARY KEY,
    realm_id text NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    event_time bigint NOT NULL,
    event_type text NOT NULL CHECK (octet_length(event_type) BETWEEN 1 AND 255),
    client_id text CHECK (octet_length(client_id) <= 255),
    user_id text CHECK (octet_length(user_id) <= 255),
    session_id text CHECK (octet_length(session_id) <= 255),
    ip_address text CHECK (octet_length(ip_address) <= 255),
    error text CHECK (octet_length(error) <= 255),
    details jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX login_events_realm_time ON login_events(realm_id, event_time);
