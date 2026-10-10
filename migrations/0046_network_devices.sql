-- OpenVIBES platform schema version 46: network device alarms (UniFi
-- IPS/IDS through openvibes-netlog; spec 2026-10-10-network-device-alarms).
-- Additive only: a new table, nullable columns, relaxed NOT NULLs, wider
-- CHECKs, a role and its grants.

-- A router or firewall that sends events. Identity is its address; a
-- removed device keeps its row because alarms point at it.
CREATE TABLE devices (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    kind text NOT NULL CHECK (kind IN ('unifi')),
    address inet NOT NULL CHECK (masklen(address) = CASE family(address) WHEN 4 THEN 32 ELSE 128 END),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    removed_by text,
    removed_at timestamptz,
    last_seen timestamptz,
    received bigint NOT NULL DEFAULT 0,
    alarms bigint NOT NULL DEFAULT 0,
    not_cef bigint NOT NULL DEFAULT 0,
    unparsed bigint NOT NULL DEFAULT 0,
    dropped_other bigint NOT NULL DEFAULT 0,
    mismatch bigint NOT NULL DEFAULT 0,
    -- Dropped events per "class:subCategory" (and "risk:<value>"), ≤ 64 keys.
    dropped_classes jsonb NOT NULL DEFAULT '{}',
    CHECK ((removed_at IS NULL) = (removed_by IS NULL))
);
CREATE UNIQUE INDEX devices_active_address_key ON devices (address) WHERE removed_at IS NULL;

-- Alarms from a device: no agent, no process; the network fields instead.
ALTER TABLE alarms
    ADD COLUMN source text NOT NULL DEFAULT 'agent' CHECK (source IN ('agent', 'device')),
    ADD COLUMN device_id bigint REFERENCES devices,
    ADD COLUMN network jsonb,
    ALTER COLUMN agent_id DROP NOT NULL,
    ALTER COLUMN process DROP NOT NULL,
    ALTER COLUMN ancestors DROP NOT NULL,
    ADD CONSTRAINT alarms_source_fields_check CHECK (
        (source = 'agent' AND agent_id IS NOT NULL AND process IS NOT NULL
            AND ancestors IS NOT NULL AND device_id IS NULL AND network IS NULL)
        OR (source = 'device' AND device_id IS NOT NULL AND network IS NOT NULL
            AND agent_id IS NULL AND process IS NULL AND ancestors IS NULL));
-- (agent_id, alarm_id, first_seen_day) is unique for agents; this is the
-- same for devices and serves netlog's lookup before insert.
CREATE UNIQUE INDEX alarms_device_alarm_key ON alarms (device_id, alarm_id, first_seen_day);

-- `device`: one device; `signature`: the rule on any device. Both only for
-- device rule sets.
ALTER TABLE alarm_suppressions
    ADD COLUMN device_id bigint REFERENCES devices,
    DROP CONSTRAINT alarm_suppressions_scope_check,
    DROP CONSTRAINT alarm_suppressions_check,
    ADD CONSTRAINT alarm_suppressions_scope_check
        CHECK (scope IN ('host', 'program', 'command', 'device', 'signature')),
    ADD CONSTRAINT alarm_suppressions_scope_fields_check CHECK (
        (scope = 'host' AND agent_id IS NOT NULL AND exe IS NULL AND args_sha256 IS NULL AND device_id IS NULL)
        OR (scope = 'program' AND agent_id IS NULL AND exe IS NOT NULL AND args_sha256 IS NULL AND device_id IS NULL)
        OR (scope = 'command' AND agent_id IS NULL AND exe IS NOT NULL AND args_sha256 IS NOT NULL AND device_id IS NULL)
        OR (scope = 'device' AND device_id IS NOT NULL AND agent_id IS NULL AND exe IS NULL AND args_sha256 IS NULL
            AND rule_set_id LIKE 'device-%')
        OR (scope = 'signature' AND device_id IS NULL AND agent_id IS NULL AND exe IS NULL AND args_sha256 IS NULL
            AND rule_set_id LIKE 'device-%'));

DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openvibes-netlog') THEN
        CREATE ROLE "openvibes-netlog" LOGIN;
    END IF;
-- Roles are cluster-wide: parallel migrations (tests) can race on creation.
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;
GRANT SELECT ON schema_version TO "openvibes-netlog";
GRANT SELECT ON devices TO "openvibes-netlog";
GRANT UPDATE (last_seen, received, alarms, not_cef, unparsed, dropped_other, mismatch, dropped_classes)
    ON devices TO "openvibes-netlog";
GRANT SELECT, INSERT, UPDATE ON alarms TO "openvibes-netlog";
GRANT INSERT ON alarm_triage_history TO "openvibes-netlog";
GRANT SELECT ON alarm_suppressions TO "openvibes-netlog";
