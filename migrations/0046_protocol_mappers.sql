-- Client protocol mappers, as the reference's PROTOCOL_MAPPER table: a
-- mapper type and its string configuration, unique by protocol and name
-- within the client, removed with the client.
CREATE TABLE client_protocol_mappers (
    realm_id text NOT NULL,
    client_id text NOT NULL,
    id text NOT NULL,
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 255),
    protocol text NOT NULL CHECK (octet_length(protocol) BETWEEN 1 AND 255),
    mapper_type text NOT NULL CHECK (octet_length(mapper_type) BETWEEN 1 AND 255),
    config jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (realm_id, client_id, id),
    UNIQUE (realm_id, client_id, protocol, name),
    FOREIGN KEY (realm_id, client_id) REFERENCES clients(realm_id, id) ON DELETE CASCADE
);
