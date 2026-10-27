-- OpenVIBES platform schema version 66: ports in cases (roles plan
-- 2026-10-25 step 5e, ruling 14). A port is a fleet-wide item like
-- software: ref `tcp/22`, no agent, no outcome, any number of open cases;
-- the hosts in a case decide who sees it. The kind check gains `port`,
-- and the "no agent" check covers both fleet-wide kinds. Only widens
-- checks, so no existing row can fail them.
ALTER TABLE case_items DROP CONSTRAINT case_items_kind_check;
ALTER TABLE case_items ADD CONSTRAINT case_items_kind_check
    CHECK (kind IN ('alarm', 'compliance_finding', 'vulnerability', 'host', 'software', 'port'));

-- The unnamed table check `(kind = 'software') = (agent_id IS NULL)`.
DO $$
DECLARE c text;
BEGIN
    FOR c IN SELECT conname FROM pg_constraint
             WHERE conrelid = 'case_items'::regclass AND contype = 'c'
               AND pg_get_constraintdef(oid) LIKE '%agent_id IS NULL%'
    LOOP
        EXECUTE format('ALTER TABLE case_items DROP CONSTRAINT %I', c);
    END LOOP;
END $$;
ALTER TABLE case_items ADD CONSTRAINT case_items_fleet_wide_check
    CHECK ((kind IN ('software', 'port')) = (agent_id IS NULL));
