-- OpenVIBES platform schema version 5: findings name the rule set that
-- produced them (protocol P6). Rule ids are unique only within a rule set, so
-- current state is kept per agent, rule set, and rule. '' means unknown (a
-- finding from a sender before P6).
ALTER TABLE findings ADD COLUMN rule_set_id text NOT NULL DEFAULT '';
ALTER TABLE current_findings ADD COLUMN rule_set_id text NOT NULL DEFAULT '';
ALTER TABLE current_findings DROP CONSTRAINT current_findings_pkey;
ALTER TABLE current_findings ADD PRIMARY KEY (agent_id, rule_set_id, rule_id);
