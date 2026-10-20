-- openvibes: needs-backup
-- OpenVIBES platform schema version 55: suppressions with approval (roles
-- spec §8): a state, a where (host, group or all hosts), a duration and the
-- source alarm. Every old row becomes active from its creation; a removed
-- one becomes removed (§12.5).
ALTER TABLE alarm_suppressions
    ADD COLUMN state text NOT NULL DEFAULT 'active'
        CHECK (state IN ('waiting', 'active', 'rejected', 'withdrawn', 'removed')),
    ADD COLUMN host_group_id uuid,
    ADD COLUMN for_days integer CHECK (for_days IN (7, 30)),
    ADD COLUMN activated_at timestamptz,
    ADD COLUMN expires_at timestamptz,
    ADD COLUMN decided_by text,
    ADD COLUMN decided_at timestamptz,
    ADD COLUMN decision_reason text CHECK (length(decision_reason) BETWEEN 1 AND 4000),
    -- The platform's alarm row id; alarms is partitioned, so no foreign key.
    ADD COLUMN alarm_id bigint;

UPDATE alarm_suppressions SET state = 'removed' WHERE removed_at IS NOT NULL;
UPDATE alarm_suppressions SET activated_at = created_at WHERE activated_at IS NULL;
ALTER TABLE alarm_suppressions ALTER COLUMN state DROP DEFAULT;

ALTER TABLE alarm_suppressions
    ADD CONSTRAINT alarm_suppressions_removed_state_check
        CHECK ((state = 'removed') = (removed_at IS NOT NULL)),
    ADD CONSTRAINT alarm_suppressions_active_check
        CHECK (state NOT IN ('active', 'removed') OR activated_at IS NOT NULL),
    ADD CONSTRAINT alarm_suppressions_rejected_check
        CHECK (state <> 'rejected' OR decision_reason IS NOT NULL);

-- program/command may now be for one host or one group (never both);
-- host/device/signature keep their old shapes (schema 46).
ALTER TABLE alarm_suppressions DROP CONSTRAINT alarm_suppressions_scope_fields_check;
ALTER TABLE alarm_suppressions ADD CONSTRAINT alarm_suppressions_scope_fields_check CHECK (
    (scope = 'host' AND agent_id IS NOT NULL AND host_group_id IS NULL AND exe IS NULL
        AND args_sha256 IS NULL AND device_id IS NULL)
 OR (scope = 'program' AND exe IS NOT NULL AND args_sha256 IS NULL AND device_id IS NULL
        AND NOT (agent_id IS NOT NULL AND host_group_id IS NOT NULL))
 OR (scope = 'command' AND exe IS NOT NULL AND args_sha256 IS NOT NULL AND device_id IS NULL
        AND NOT (agent_id IS NOT NULL AND host_group_id IS NOT NULL))
 OR (scope = 'device' AND device_id IS NOT NULL AND agent_id IS NULL AND host_group_id IS NULL
        AND exe IS NULL AND args_sha256 IS NULL AND rule_set_id LIKE 'device-%')
 OR (scope = 'signature' AND device_id IS NULL AND agent_id IS NULL AND host_group_id IS NULL
        AND exe IS NULL AND args_sha256 IS NULL AND rule_set_id LIKE 'device-%'));

DROP INDEX alarm_suppressions_active_idx;
CREATE INDEX alarm_suppressions_active_idx ON alarm_suppressions (rule_set_id, rule_id)
    WHERE state = 'active';
CREATE INDEX alarm_suppressions_waiting_idx ON alarm_suppressions (created_at)
    WHERE state = 'waiting';

-- Activation closes the source alarm (plan ruling 3), as ingest does.
GRANT UPDATE (suppressed_by) ON alarms TO "openvibes-console";

-- Ingest matches group suppressions with console_host_in_group, which runs
-- with the caller's rights and reads manual group members.
GRANT SELECT ON console_host_group_members TO "openvibes-ingest";
