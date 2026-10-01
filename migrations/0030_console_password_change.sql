-- OpenVIBES platform schema version 30: a console user can be required to set
-- their own password at the next sign-in (a one-time password from the
-- console's New user). Additive only: one column with a default.
ALTER TABLE console_users ADD COLUMN password_must_change boolean NOT NULL DEFAULT false;
