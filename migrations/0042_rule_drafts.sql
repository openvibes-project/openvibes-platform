-- OpenVIBES platform schema version 42: draft rules for the console's own
-- rule sets (board #19 / #107, own rules). A draft is one rule of the
-- site's findings set (`site`) or alarm set (`site-alarms`), saved but not
-- yet published. Publishing signs the set through the rule signer and is a
-- later step; a draft never reaches an agent.
CREATE TABLE rule_drafts (
    rule_set_id text NOT NULL CHECK (rule_set_id IN ('site', 'site-alarms')),
    rule_id text NOT NULL CHECK (char_length(rule_id) BETWEEN 1 AND 128),
    -- The rule as the agent's loader reads it (`openvibes_core::Rule`).
    rule jsonb NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_set_id, rule_id)
);

-- Writing drafts is separate from publishing (`rules.upload`), so one
-- person can write and another publish.
INSERT INTO console_permissions (permission_id, scope_class)
VALUES ('rules.write', 'global')
ON CONFLICT (permission_id) DO NOTHING;
INSERT INTO console_role_permissions (role_id, permission_id)
VALUES ('operator', 'rules.write'), ('admin', 'rules.write')
ON CONFLICT DO NOTHING;

GRANT SELECT, INSERT, UPDATE, DELETE ON rule_drafts TO "openvibes-console";
