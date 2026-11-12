-- Realm event settings, as the reference's RealmModel: login and admin
-- events off by default, the jboss-logging listener, and an empty list of
-- enabled event types, which stands for the types saved by default.
ALTER TABLE realms ADD COLUMN events_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN events_expiration bigint;
ALTER TABLE realms ADD COLUMN events_listeners text[] NOT NULL DEFAULT '{jboss-logging}';
ALTER TABLE realms ADD COLUMN enabled_event_types text[] NOT NULL DEFAULT '{}';
ALTER TABLE realms ADD COLUMN admin_events_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE realms ADD COLUMN admin_events_details_enabled boolean NOT NULL DEFAULT false;
