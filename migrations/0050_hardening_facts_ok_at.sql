-- openvibes: needs-backup
-- OpenVIBES platform schema version 50: when a host's stored health report
-- last had usable hardening facts (the root-facts helper, P19), so the
-- console can say for how long they have been missing (rule-set assignment
-- console plan, ruling G1). Set by ingest; the agent reports no such time.
-- The console reads and ingest updates `agents` through their table grants.
ALTER TABLE agents ADD COLUMN hardening_facts_ok_at timestamptz;
UPDATE agents SET hardening_facts_ok_at = health_at
 WHERE health -> 'last_scan' -> 'collectors' ->> 'hardening' = 'ok';
