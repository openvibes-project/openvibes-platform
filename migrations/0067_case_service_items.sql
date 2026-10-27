-- OpenVIBES platform schema version 67: services in cases (roles plan
-- 2026-10-27 step 5f, ruling 14). A service is a fleet-wide item like
-- software and ports: ref the unit (`sshd.service`), no agent, no outcome,
-- any number of open cases; the hosts in a case decide who sees it. The
-- kind check gains `service`, and the "no agent" check covers all three
-- fleet-wide kinds. Only widens checks, so no existing row can fail them.
ALTER TABLE case_items DROP CONSTRAINT case_items_kind_check;
ALTER TABLE case_items ADD CONSTRAINT case_items_kind_check
    CHECK (kind IN ('alarm', 'compliance_finding', 'vulnerability', 'host', 'software', 'port', 'service'));

ALTER TABLE case_items DROP CONSTRAINT case_items_fleet_wide_check;
ALTER TABLE case_items ADD CONSTRAINT case_items_fleet_wide_check
    CHECK ((kind IN ('software', 'port', 'service')) = (agent_id IS NULL));
