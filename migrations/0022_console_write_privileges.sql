-- OpenVIBES platform schema version 22: let the console's own store
-- operations replace selectors/tags, clean up idempotency rows, lock mutable
-- store records, revoke agents, and publish verified rule bundles.
GRANT DELETE ON console_idempotency, console_asset_group_selectors,
    console_agent_tags TO openvibes_console;
GRANT UPDATE ON agents, current_findings, rule_sets, rule_trust_keys
    TO openvibes_console;
GRANT INSERT ON rule_bundles TO openvibes_console;
