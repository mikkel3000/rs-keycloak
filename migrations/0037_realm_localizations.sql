-- Realm localization texts: per locale, keys whose texts override the login
-- theme's messages, as the reference's REALM_LOCALIZATIONS keeps them. A
-- locale stays listed after its last text is removed.
CREATE TABLE realm_localizations (
    realm_id text NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    locale text NOT NULL CHECK (octet_length(locale) BETWEEN 1 AND 255),
    texts jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(texts) = 'object' AND octet_length(texts::text) <= 1048576),
    PRIMARY KEY (realm_id, locale)
);
