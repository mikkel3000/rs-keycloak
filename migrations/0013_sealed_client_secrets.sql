-- Confidential clients keep either a legacy Argon2id hash or a recoverable
-- AES-256-GCM sealed secret bound to the client row, never both.
ALTER TABLE clients ADD COLUMN secret_sealed bytea CHECK (octet_length(secret_sealed) BETWEEN 29 AND 4096);
ALTER TABLE clients ADD COLUMN secret_key_id text CHECK (octet_length(secret_key_id) BETWEEN 1 AND 64);
ALTER TABLE clients DROP CONSTRAINT clients_secret_type;
ALTER TABLE clients ADD CONSTRAINT clients_secret_type CHECK (
    (secret_sealed IS NULL) = (secret_key_id IS NULL) AND (
        (public_client AND secret_phc IS NULL AND secret_sealed IS NULL) OR
        (NOT public_client AND secret_phc IS NOT NULL AND octet_length(secret_phc) BETWEEN 1 AND 4096 AND secret_sealed IS NULL) OR
        (NOT public_client AND secret_phc IS NULL AND secret_sealed IS NOT NULL)
    )
);
-- Clients may opt out of the browser authorization-code flow.
ALTER TABLE clients ADD COLUMN standard_flow_enabled boolean NOT NULL DEFAULT true;
