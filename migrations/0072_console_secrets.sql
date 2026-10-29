-- Secrets the console itself uses (TUI rework step 6c: the assistant's API
-- key). The console process reads them to connect, so its role may read this
-- table, unlike service_secrets (written, never read, by the console). The
-- API never returns a value, and no other service role has any access.
CREATE TABLE console_secrets (
    key text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    value text NOT NULL,
    changed_at timestamptz NOT NULL,
    changed_by text NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON console_secrets TO "openvibes-console";
