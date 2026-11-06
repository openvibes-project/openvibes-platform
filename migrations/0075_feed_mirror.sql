-- Reading a feed mirror (openvibes-protocol spec/feed-v1.md, Pinning): the
-- vulnerability service pins the key a mirror presents on first contact, so
-- the site's trust is the address it set. A pinned key is marked, so the
-- status can say so and a second pin is never taken. The service also
-- records one audit row per feed it applies or refuses.
ALTER TABLE feed_trust_keys ADD COLUMN pinned boolean NOT NULL DEFAULT false;
GRANT INSERT ON feed_trust_keys TO "openvibes-vulns";
GRANT INSERT ON audit_log TO "openvibes-vulns";
GRANT USAGE ON SEQUENCE audit_log_id_seq TO "openvibes-vulns";
