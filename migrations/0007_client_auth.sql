ALTER TABLE clients ADD COLUMN revision bigint NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN secret_phc bytea;
ALTER TABLE clients ADD CONSTRAINT clients_secret_type CHECK (
    (public_client AND secret_phc IS NULL) OR
    (NOT public_client AND secret_phc IS NOT NULL AND octet_length(secret_phc) BETWEEN 1 AND 4096)
);
CREATE FUNCTION rs_bump_client_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.revision := OLD.revision + 1;
    RETURN NEW;
END
$$;
CREATE TRIGGER rs_client_revision BEFORE UPDATE ON clients FOR EACH ROW EXECUTE FUNCTION rs_bump_client_revision();
