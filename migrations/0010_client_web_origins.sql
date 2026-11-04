CREATE TABLE client_web_origins (
    realm_id text NOT NULL,
    client_id text NOT NULL,
    origin text COLLATE "C" NOT NULL CHECK (octet_length(origin) BETWEEN 1 AND 2048 AND origin <> '*' AND origin <> 'null'),
    PRIMARY KEY (realm_id, client_id, origin),
    FOREIGN KEY (realm_id, client_id) REFERENCES clients(realm_id, id) ON DELETE CASCADE
);
