-- OpenVIBES platform schema version 63: the Compliance list by check (roles
-- plan 2026-10-24 step 5c, rulings 3 and 18). The failing pairs of one check
-- (open current findings of a rule set and rule), each indexed rule's
-- severity (the severity of a check no host in reach has a finding for;
-- NULL until the console re-indexes the bundle, which its start-up backfill
-- does for rows without one), and the SQL twin of the store's `check_area`
-- (check_area.rs; a test keeps the two equal over every baseline and
-- hardening rule ID). Additive.
CREATE INDEX current_findings_open_check
    ON current_findings (rule_set_id, rule_id) WHERE ended_at IS NULL;

-- The list hashes the findings per check, severity and host class; without
-- the joint distinct count the planner multiplied the columns' counts,
-- expected 170,000 groups instead of about 400, and sorted the 500,000 rows
-- on disk (1.5 s instead of 0.9 s at the step 5c ruling 18 size).
CREATE STATISTICS current_findings_check (ndistinct)
    ON rule_set_id, rule_id, severity FROM current_findings;

ALTER TABLE console_rule_meta ADD COLUMN severity text
    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'));

CREATE FUNCTION console_check_area(rule_id text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE
    WHEN starts_with(rule_id, 'port.') THEN 'Network exposure'
    WHEN starts_with(rule_id, 'package.') THEN 'Packages'
    WHEN starts_with(rule_id, 'harden.ssh.') THEN 'SSH'
    WHEN starts_with(rule_id, 'harden.net.') THEN 'Network'
    WHEN starts_with(rule_id, 'harden.kernel.') OR starts_with(rule_id, 'harden.modules.') THEN 'Kernel'
    WHEN starts_with(rule_id, 'harden.files.') OR starts_with(rule_id, 'harden.fs.') THEN 'Files'
    WHEN starts_with(rule_id, 'harden.accounts.') OR starts_with(rule_id, 'harden.login.') THEN 'Accounts'
    WHEN starts_with(rule_id, 'harden.lsm.') THEN 'Security modules'
    WHEN starts_with(rule_id, 'harden.services.') THEN 'Services'
    WHEN starts_with(rule_id, 'test.') THEN 'Tests'
    ELSE 'Other' END $$;
GRANT EXECUTE ON FUNCTION console_check_area(text) TO "openvibes-console";
