-- OpenVIBES platform schema version 49: rule-set assignment (spec
-- 2026-10-14-rule-set-assignment-design.md). The project's assignable rule
-- sets with their default, and on/off overrides per asset group. On a host,
-- any matching group that says on wins, else any that says off, else the
-- default. No foreign key to rule_sets: a set is assignable before its
-- rules are published (L2 shows "not available yet").
CREATE TABLE rule_set_assignment (
    rule_set_id text PRIMARY KEY CHECK (length(rule_set_id) BETWEEN 1 AND 128),
    default_enabled boolean NOT NULL
);
CREATE TABLE rule_set_group_assignment (
    rule_set_id text NOT NULL REFERENCES rule_set_assignment ON DELETE CASCADE,
    asset_group_id uuid NOT NULL REFERENCES console_asset_groups ON DELETE CASCADE,
    enabled boolean NOT NULL,
    PRIMARY KEY (rule_set_id, asset_group_id)
);
INSERT INTO rule_set_assignment (rule_set_id, default_enabled) VALUES
    ('hardening-linux-l1', true), ('hardening-linux-l2', false);
REVOKE ALL ON rule_set_assignment, rule_set_group_assignment FROM PUBLIC;
-- The console switches defaults and overrides (rules.upload).
GRANT SELECT, UPDATE ON rule_set_assignment TO "openvibes-console";
GRANT SELECT, INSERT, UPDATE, DELETE ON rule_set_group_assignment TO "openvibes-console";
-- Distribution answers 410 for a set that is off on the asking host: it
-- reads the switches and only the tag and selector columns membership needs.
GRANT SELECT ON rule_set_assignment, rule_set_group_assignment TO "openvibes-distribution";
GRANT SELECT (agent_id, tag_key, tag_value) ON console_agent_tags TO "openvibes-distribution";
GRANT SELECT (asset_group_id, tag_key, tag_value) ON console_asset_group_selectors
    TO "openvibes-distribution";
-- Ingest ends a host's matches of a set the agent reports not_assigned: it
-- checks the set is assignable (it already updates current_findings and
-- writes triage history).
GRANT SELECT ON rule_set_assignment TO "openvibes-ingest";
