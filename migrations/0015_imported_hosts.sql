-- OpenVIBES platform schema version 15: hosts imported from agent export
-- files (protocol P3b; spec docs/specs/2026-09-27-file-import-design.md).
-- An imported host never authenticates: certificates only name agent.<uuid>,
-- and an import. id is only valid with status imported.
ALTER TABLE agents
    DROP CONSTRAINT agents_agent_id_check,
    DROP CONSTRAINT agents_status_check,
    ADD CONSTRAINT agents_status_check CHECK (status IN ('active', 'revoked', 'imported')),
    ADD CONSTRAINT agents_agent_id_check CHECK (
        (status <> 'imported' AND agent_id ~ '^agent\.[0-9a-f-]{36}$')
        OR (status = 'imported' AND agent_id ~ '^import\.[A-Za-z0-9._:-]{1,128}$')),
    ADD COLUMN claimed_agent_id text;
