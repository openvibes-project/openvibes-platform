-- OpenVIBES platform schema version 22: console replacement and publication
-- writes. Column-scoped lock privileges are added in schema version 23.
GRANT DELETE ON console_idempotency, console_asset_group_selectors,
    console_agent_tags TO openvibes_console;
GRANT INSERT ON rule_bundles TO openvibes_console;
