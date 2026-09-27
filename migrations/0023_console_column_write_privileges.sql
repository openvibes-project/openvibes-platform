-- OpenVIBES platform schema version 23: row-lock privileges are column-scoped
-- so the console role cannot edit unrelated agent, finding, or trust data.
REVOKE UPDATE ON agents, current_findings, rule_sets, rule_trust_keys
    FROM openvibes_console;
GRANT UPDATE (status, revoked_at) ON agents TO openvibes_console;
GRANT UPDATE (received_at) ON current_findings TO openvibes_console;
GRANT UPDATE (created_at) ON rule_sets TO openvibes_console;
GRANT UPDATE (added_at) ON rule_trust_keys TO openvibes_console;
