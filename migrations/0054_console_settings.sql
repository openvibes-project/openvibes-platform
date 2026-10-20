-- General settings (roles spec §7): one row per changed key; a key with no
-- row has its default, which lives in the console's definitions.
CREATE TABLE console_settings (
    key text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    value jsonb NOT NULL,
    changed_at timestamptz NOT NULL,
    changed_by text NOT NULL
);
GRANT SELECT, INSERT, UPDATE ON console_settings TO "openvibes-console";
