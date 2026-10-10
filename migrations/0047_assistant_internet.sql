-- OpenVIBES platform schema version 47: assistant internet lookups
-- (spec 2026-10-10-assistant-internet-lookups). One row, off by default.
CREATE TABLE assistant_internet (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    level smallint NOT NULL DEFAULT 0 CHECK (level BETWEEN 0 AND 2),
    searxng_url text CHECK (searxng_url IS NULL OR length(searxng_url) <= 512),
    internal_domains text[] NOT NULL DEFAULT '{}'
        CHECK (cardinality(internal_domains) <= 50),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at timestamptz NOT NULL,
    updated_by text NOT NULL,
    CHECK (level < 2 OR searxng_url IS NOT NULL)
);
INSERT INTO assistant_internet (singleton, updated_at, updated_by)
VALUES (true, now(), 'migration');

INSERT INTO console_permissions (permission_id, scope_class)
VALUES ('assistant.admin', 'global');
INSERT INTO console_role_permissions (role_id, permission_id)
VALUES ('admin', 'assistant.admin');
GRANT SELECT ON assistant_internet TO "openvibes-console";
GRANT UPDATE (level, searxng_url, internal_domains, version, updated_at, updated_by)
    ON assistant_internet TO "openvibes-console";

DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openvibes-fetch') THEN
        CREATE ROLE "openvibes-fetch" LOGIN;
    END IF;
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;
-- The fetch service reads the level and the filter's terms, nothing else.
GRANT SELECT ON assistant_internet TO "openvibes-fetch";
GRANT SELECT (agent_id, hostname) ON agents TO "openvibes-fetch";
GRANT SELECT (username) ON console_users TO "openvibes-fetch";
GRANT SELECT ON schema_version TO "openvibes-fetch";
