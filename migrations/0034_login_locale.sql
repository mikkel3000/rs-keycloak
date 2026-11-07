-- An authorization request keeps the client's ui_locales and the locale the
-- user picked with kc_locale, as the reference keeps them in the
-- authentication session's notes.
ALTER TABLE authorization_requests ADD COLUMN ui_locales text CHECK (octet_length(ui_locales) <= 2048);
ALTER TABLE authorization_requests ADD COLUMN requested_locale text CHECK (octet_length(requested_locale) BETWEEN 1 AND 255);
