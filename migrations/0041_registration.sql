-- registrationAllowed, as the reference's realm setting: the login page
-- links to a registration form that makes and signs in a user.
ALTER TABLE realms ADD COLUMN registration_allowed boolean NOT NULL DEFAULT false;
