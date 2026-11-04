-- Registered post-logout redirect URIs; the flag reproduces Keycloak's "+",
-- which accepts every current redirect URI of the client.
CREATE TABLE client_post_logout_redirect_uris (
    realm_id text NOT NULL,
    client_id text NOT NULL,
    redirect_uri text NOT NULL CHECK (octet_length(redirect_uri) BETWEEN 1 AND 2048),
    PRIMARY KEY (realm_id, client_id, redirect_uri),
    FOREIGN KEY (realm_id, client_id) REFERENCES clients(realm_id, id) ON DELETE CASCADE
);
ALTER TABLE clients ADD COLUMN post_logout_uses_redirect_uris boolean NOT NULL DEFAULT false;
