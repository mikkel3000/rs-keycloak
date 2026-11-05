-- Admins may now act from the realm they manage. Admin events name their
-- actor by identifier, as the reference's admin events do, so deleting the
-- actor keeps the history, and a deleted realm takes its events with it.
ALTER TABLE audit_events DROP CONSTRAINT audit_events_realm_id_actor_user_id_fkey;
ALTER TABLE audit_events DROP CONSTRAINT audit_events_realm_id_fkey;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_realm_id_fkey FOREIGN KEY (realm_id) REFERENCES realms(id) ON DELETE CASCADE;
