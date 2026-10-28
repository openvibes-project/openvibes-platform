-- OpenVIBES platform schema version 69: profile pictures (roles spec
-- 2026-10-16 §9.2, step 7). A person's picture is kept only as the two WebP
-- images the picture helper produced (256 and 64 px); the original is never
-- stored. `etag` is the SHA-256 of both, hex, for HTTP caching and for the
-- console to tell a changed picture from the old one.
CREATE TABLE console_user_pictures (
  user_id uuid PRIMARY KEY REFERENCES console_users ON DELETE CASCADE,
  large bytea NOT NULL CHECK (octet_length(large) BETWEEN 1 AND 3145728),
  small bytea NOT NULL CHECK (octet_length(small) BETWEEN 1 AND 3145728),
  etag text NOT NULL CHECK (etag ~ '^[0-9a-f]{64}$'),
  animated boolean NOT NULL,
  updated_at timestamptz NOT NULL,
  updated_by text NOT NULL);
GRANT SELECT, INSERT, UPDATE, DELETE ON console_user_pictures TO "openvibes-console";
