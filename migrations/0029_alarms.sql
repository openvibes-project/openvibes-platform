-- OpenVIBES platform schema version 29: threat alarms (protocol P14).
-- Additive only: new tables, one nullable column, permissions and grants.

-- Suppressions come first: alarms point at the one that closed them.
-- `program` and `command` apply on any host, `host` to one agent; a
-- removed suppression keeps its row as history.
CREATE TABLE alarm_suppressions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_set_id text NOT NULL,
    rule_id text NOT NULL,
    scope text NOT NULL CHECK (scope IN ('host', 'program', 'command')),
    agent_id text,
    exe text,
    args_sha256 text CHECK (args_sha256 ~ '^[0-9a-f]{64}$'),
    note text NOT NULL CHECK (length(note) BETWEEN 1 AND 4000),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    removed_by text,
    removed_at timestamptz,
    CHECK ((scope = 'host' AND agent_id IS NOT NULL AND exe IS NULL AND args_sha256 IS NULL)
        OR (scope = 'program' AND agent_id IS NULL AND exe IS NOT NULL AND args_sha256 IS NULL)
        OR (scope = 'command' AND agent_id IS NULL AND exe IS NOT NULL AND args_sha256 IS NOT NULL)),
    CHECK ((removed_at IS NULL) = (removed_by IS NULL))
);
CREATE INDEX alarm_suppressions_active_idx
    ON alarm_suppressions (rule_set_id, rule_id) WHERE removed_at IS NULL;

-- One row per alarm, partitioned by the day of `first_seen` and dropped
-- with the same retention as findings. `id` is the platform's key for the
-- console; `alarm_id` is the agent's and only unique per agent. Triage
-- lives on the row itself, so it leaves with its partition.
CREATE TABLE alarms (
    id bigint GENERATED ALWAYS AS IDENTITY,
    first_seen_day date NOT NULL,
    agent_id text NOT NULL,
    alarm_id text NOT NULL,
    rule_set_id text NOT NULL,
    rule_set_version bigint NOT NULL CHECK (rule_set_version >= 0),
    rule_id text NOT NULL,
    rule_version bigint NOT NULL CHECK (rule_version >= 0),
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence smallint NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    message text NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    count bigint NOT NULL CHECK (count > 0),
    process jsonb NOT NULL,
    ancestors jsonb NOT NULL,
    received_at timestamptz NOT NULL,
    suppressed_by bigint REFERENCES alarm_suppressions,
    state text NOT NULL DEFAULT 'open'
        CHECK (state IN ('open', 'investigating', 'mitigated', 'accepted_risk', 'false_positive')),
    assigned_to uuid REFERENCES console_users,
    note text,
    accepted_until timestamptz,
    triage_version bigint NOT NULL DEFAULT 1 CHECK (triage_version > 0),
    triage_updated_at timestamptz,
    triage_updated_by text,
    PRIMARY KEY (id, first_seen_day),
    UNIQUE (agent_id, alarm_id, first_seen_day),
    CHECK (first_seen_day = (first_seen AT TIME ZONE 'UTC')::date),
    CHECK (last_seen >= first_seen),
    CHECK ((state IN ('open', 'investigating')) OR (note IS NOT NULL AND length(note) BETWEEN 1 AND 4000)),
    CHECK ((state = 'accepted_risk') = (accepted_until IS NOT NULL))
) PARTITION BY RANGE (first_seen_day);
-- Ingest looks an alarm up by the agent's id before inserting, so a resend
-- with a different first_seen never makes a second row.
CREATE INDEX alarms_agent_alarm_idx ON alarms (agent_id, alarm_id);
CREATE INDEX alarms_newest_idx ON alarms (last_seen DESC, id DESC);
CREATE INDEX alarms_agent_newest_idx ON alarms (agent_id, last_seen DESC, id DESC);
CREATE INDEX alarms_rule_idx ON alarms (rule_set_id, rule_id);

-- Triage history, partitioned by its alarm's day so it leaves with it.
CREATE TABLE alarm_triage_history (
    event_id bigint GENERATED ALWAYS AS IDENTITY,
    first_seen_day date NOT NULL,
    alarm_id bigint NOT NULL,
    from_state text CHECK (from_state IS NULL OR from_state IN ('open', 'investigating', 'mitigated', 'accepted_risk', 'false_positive')),
    to_state text NOT NULL CHECK (to_state IN ('open', 'investigating', 'mitigated', 'accepted_risk', 'false_positive')),
    assigned_to uuid REFERENCES console_users,
    accepted_until timestamptz,
    note text CHECK (note IS NULL OR length(note) BETWEEN 1 AND 4000),
    changed_at timestamptz NOT NULL,
    changed_by text NOT NULL,
    PRIMARY KEY (event_id, first_seen_day)
) PARTITION BY RANGE (first_seen_day);
CREATE INDEX alarm_triage_history_alarm_idx
    ON alarm_triage_history (alarm_id, event_id DESC);

-- The largest `dropped_total` the agent has reported (contract: keep the
-- largest). Ingest already holds UPDATE on agents (0001).
ALTER TABLE agents ADD COLUMN alarms_dropped_total bigint
    CHECK (alarms_dropped_total >= 0);

INSERT INTO console_permissions (permission_id, scope_class)
VALUES ('alarms.read', 'agent'), ('alarms.triage', 'agent'), ('alarms.suppress', 'agent')
ON CONFLICT (permission_id) DO NOTHING;
INSERT INTO console_role_permissions (role_id, permission_id)
VALUES ('viewer', 'alarms.read'),
       ('analyst', 'alarms.read'), ('analyst', 'alarms.triage'), ('analyst', 'alarms.suppress'),
       ('operator', 'alarms.read'),
       ('admin', 'alarms.read'), ('admin', 'alarms.triage'), ('admin', 'alarms.suppress')
ON CONFLICT DO NOTHING;

-- Ingest stores and raises alarms and closes suppressed ones.
GRANT SELECT, INSERT, UPDATE ON alarms TO "openvibes-ingest";
GRANT INSERT ON alarm_triage_history TO "openvibes-ingest";
GRANT SELECT ON alarm_suppressions TO "openvibes-ingest";
-- The console reads alarms, triages them and manages suppressions.
GRANT SELECT ON alarms TO "openvibes-console";
GRANT UPDATE (state, assigned_to, note, accepted_until, triage_version,
    triage_updated_at, triage_updated_by) ON alarms TO "openvibes-console";
GRANT SELECT, INSERT ON alarm_triage_history TO "openvibes-console";
GRANT SELECT, INSERT, UPDATE ON alarm_suppressions TO "openvibes-console";
