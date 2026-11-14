-- Stored admin events, as the reference's ADMIN_EVENT_ENTITY: changes made
-- through the admin API in a realm with admin events on, with who made
-- them, removed with the realm. Times are epoch milliseconds.
CREATE TABLE admin_events (
    id text PRIMARY KEY,
    realm_id text NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    event_time bigint NOT NULL,
    operation_type text NOT NULL CHECK (operation_type IN ('CREATE', 'UPDATE', 'DELETE', 'ACTION')),
    resource_type text NOT NULL CHECK (octet_length(resource_type) BETWEEN 1 AND 64),
    resource_path text CHECK (octet_length(resource_path) <= 2048),
    representation text,
    auth_realm_id text NOT NULL,
    auth_client_id text,
    auth_user_id text NOT NULL,
    ip_address text CHECK (octet_length(ip_address) <= 255)
);
CREATE INDEX admin_events_realm_time ON admin_events(realm_id, event_time);
