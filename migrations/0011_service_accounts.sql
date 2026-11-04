-- Confidential clients may own one service-account user for the client-credentials grant.
ALTER TABLE clients ADD COLUMN service_accounts_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE clients ADD CONSTRAINT clients_service_accounts_confidential CHECK (NOT service_accounts_enabled OR NOT public_client);
ALTER TABLE users ADD COLUMN service_account_client_id text;
ALTER TABLE users ADD CONSTRAINT users_service_account_client FOREIGN KEY (realm_id, service_account_client_id) REFERENCES clients(realm_id, id) ON DELETE CASCADE;
CREATE UNIQUE INDEX users_service_account_client_unique ON users (realm_id, service_account_client_id) WHERE service_account_client_id IS NOT NULL;
-- Service-account tokens have no stored session; their revocations bind the account user.
ALTER TABLE revoked_access_tokens ALTER COLUMN session_id DROP NOT NULL;
ALTER TABLE revoked_access_tokens ADD COLUMN service_account_user_id text;
ALTER TABLE revoked_access_tokens ADD CONSTRAINT revoked_access_tokens_service_account FOREIGN KEY (realm_id, service_account_user_id) REFERENCES users(realm_id, id) ON DELETE CASCADE;
ALTER TABLE revoked_access_tokens ADD CONSTRAINT revoked_access_tokens_one_holder CHECK ((session_id IS NULL) <> (service_account_user_id IS NULL));
