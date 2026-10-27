-- OpenVIBES platform schema version 65: the shared change log (roles plan
-- 2026-10-25 step 5e, ruling 2). Ingest compares a host's old and new
-- packages, listening ports and services inside the transaction that
-- replaces them, and writes only the differences. A host's first report is
-- its baseline and writes nothing. Maintenance deletes rows older than 90
-- days. `key`: a listener `tcp/22`, a service its unit, a package its name
-- (`detail` = {manager, version, arch}).
CREATE TABLE change_log (
    at timestamptz NOT NULL,
    agent_id text NOT NULL REFERENCES agents (agent_id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('package', 'listener', 'service')),
    key text NOT NULL,
    change text NOT NULL CHECK (change IN ('appeared', 'went_away', 'exposed', 'local')),
    detail jsonb
);
CREATE INDEX change_log_key ON change_log (kind, key, at DESC);
CREATE INDEX change_log_at ON change_log (kind, at);
CREATE INDEX change_log_agent ON change_log (agent_id);

-- When the log began, so a page can say "before this date" for a port the
-- log never saw appear.
CREATE TABLE change_log_start (
    only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    at timestamptz NOT NULL
);
INSERT INTO change_log_start (at) VALUES (now());

GRANT INSERT ON change_log TO "openvibes-ingest";
GRANT SELECT ON change_log, change_log_start TO "openvibes-console";
