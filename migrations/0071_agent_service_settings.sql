-- The agent-facing services (ingest, rule distribution) read the console's
-- settings for the keys under their own prefix when they start (TUI rework
-- step 6b). Settings only: a secret in service_secrets stays unreadable to
-- them.
GRANT SELECT ON console_settings TO "openvibes-ingest", "openvibes-distribution";
