-- Service settings changed in the console (TUI rework step 6): the services
-- read console_settings for the keys the console's definitions name, and a
-- secret (such as the NVD API key) lives apart so no read of console_settings
-- or of the console's own role ever returns it.

-- A setting goes back to its default by deleting its row.
GRANT DELETE ON console_settings TO "openvibes-console";
GRANT SELECT ON console_settings TO "openvibes-vulns";

CREATE TABLE service_secrets (
    key text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    value text NOT NULL,
    changed_at timestamptz NOT NULL,
    changed_by text NOT NULL
);
-- The console writes a secret and may see that one is set, never its value.
GRANT SELECT (key, changed_at, changed_by), INSERT, UPDATE, DELETE ON service_secrets TO "openvibes-console";
GRANT SELECT ON service_secrets TO "openvibes-vulns";
