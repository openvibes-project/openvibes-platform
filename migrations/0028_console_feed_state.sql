-- OpenVIBES platform schema version 28: the console may read when each
-- vulnerability feed last imported (board #47), so an empty summary can say
-- "scanning is not set up" instead of "no vulnerable host". Two columns
-- only: no URLs, digests, cursors or errors.
GRANT SELECT (os_id, last_changed_at) ON feed_sources TO "openvibes-console";
