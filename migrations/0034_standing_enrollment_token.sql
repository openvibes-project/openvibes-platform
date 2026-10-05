-- OpenVIBES platform schema version 34: a standing enrollment token. One
-- long-lived token every agent may enroll with, so operators need not mint
-- short-lived ones per install. It never expires and has no use limit; it is
-- revoked (and replaced) like any other token. expires_at and max_uses stay
-- set (far future, the cap) for readers that predate the flag.
ALTER TABLE enrollment_tokens ADD COLUMN standing boolean NOT NULL DEFAULT false;
-- At most one live standing token: a second one needs the first revoked.
CREATE UNIQUE INDEX enrollment_tokens_one_standing
    ON enrollment_tokens ((true)) WHERE standing AND revoked_at IS NULL;
-- The standing token's secret, kept so `agent command` and Setup can show
-- the same install line again (other tokens are shown once and never
-- stored). No role but the owner (the admin account) is granted this table:
-- ingest and the console only ever see the hash.
CREATE TABLE standing_token_secret (
    token_id uuid PRIMARY KEY REFERENCES enrollment_tokens,
    secret text NOT NULL
);
