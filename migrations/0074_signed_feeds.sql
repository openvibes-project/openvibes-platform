-- Signed vulnerability-data feeds (openvibes-protocol spec/feed-v1.md).
-- A site trusts the Ed25519 key of its own mirror (or bundle builder) per
-- (feed id, key id); the highest accepted sequence and manifest digest are
-- kept per key so an older or altered feed cannot be applied; the last file
-- applied per source and kind keeps a stale file from coming back in.
CREATE TABLE feed_trust_keys (
    feed_id text NOT NULL CHECK (feed_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    key_id text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    public_key bytea NOT NULL CHECK (length(public_key) = 32),
    added_at timestamptz NOT NULL,
    removed_at timestamptz,
    PRIMARY KEY (feed_id, key_id)
);

CREATE TABLE feed_state (
    feed_id text NOT NULL,
    key_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence >= 1),
    manifest_digest bytea NOT NULL CHECK (length(manifest_digest) = 32),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    applied_at timestamptz NOT NULL,
    origin text NOT NULL CHECK (origin IN ('mirror', 'bundle')),
    PRIMARY KEY (feed_id, key_id),
    FOREIGN KEY (feed_id, key_id) REFERENCES feed_trust_keys
);

CREATE TABLE feed_applied_files (
    source text NOT NULL,
    kind text NOT NULL,
    sha256 bytea NOT NULL CHECK (length(sha256) = 32),
    fetched_at timestamptz NOT NULL,
    feed_id text NOT NULL,
    key_id text NOT NULL,
    sequence bigint NOT NULL,
    applied_at timestamptz NOT NULL,
    PRIMARY KEY (source, kind)
);

-- The vulnerability service reads the trusted keys and, in mirror mode,
-- keeps the state and applied files current.
GRANT SELECT ON feed_trust_keys TO "openvibes-vulns";
GRANT SELECT, INSERT, UPDATE ON feed_state, feed_applied_files TO "openvibes-vulns";
