-- SAML single sign-on (TUI rework step 7b, spec 2026-10-29 §6).
-- A person who signs in through the identity provider is a console user with
-- auth_source 'sso' and no credential; this table links the user to the
-- identity provider's stable subject (the NameID), never to a username or
-- email.
CREATE TABLE console_sso_users (
    user_id uuid PRIMARY KEY REFERENCES console_users ON DELETE CASCADE,
    issuer text NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 1024),
    subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL,
    UNIQUE (issuer, subject)
);

-- One row per sign-in started here: the request ID the identity provider
-- must answer, and the hashes of the relay token (in the browser's redirect)
-- and the browser-binding cookie. Each is used once, within five minutes.
CREATE TABLE console_saml_requests (
    relay_sha256 bytea PRIMARY KEY CHECK (length(relay_sha256) = 32),
    request_id text NOT NULL CHECK (char_length(request_id) BETWEEN 8 AND 128),
    browser_sha256 bytea NOT NULL CHECK (length(browser_sha256) = 32),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX console_saml_requests_expiry_idx ON console_saml_requests (expires_at);

-- Assertions already accepted, so one cannot be replayed while it could
-- still be valid.
CREATE TABLE console_saml_seen (
    assertion_sha256 bytea PRIMARY KEY CHECK (length(assertion_sha256) = 32),
    expires_at timestamptz NOT NULL
);
CREATE INDEX console_saml_seen_expiry_idx ON console_saml_seen (expires_at);

-- Roles that came from the identity provider's groups can be replaced at
-- each sign-in without touching roles an administrator granted by hand.
ALTER TABLE console_role_bindings
    ADD COLUMN source text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'sso'));

GRANT SELECT, INSERT, UPDATE, DELETE ON console_sso_users, console_saml_requests, console_saml_seen
    TO "openvibes-console";
