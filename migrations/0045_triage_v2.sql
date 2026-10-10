-- openvibes: needs-backup
-- OpenVIBES platform schema version 45: triage v2 (spec
-- 2026-10-10-bulk-triage-design.md, #237/#239/#240). One state model for
-- alarms, compliance findings and vulnerabilities: open, mitigated,
-- accepted_risk, false_positive, and any state moves to any other.
-- `investigating` is retired: cases cover it now.

-- 1. Retire `investigating`: such items become open (assignee, note and case
-- links kept), with one history row each saying why. History keeps the old
-- value in rows written before.
INSERT INTO alarm_triage_history (first_seen_day, alarm_row_id, from_state, to_state, note,
    changed_at, changed_by)
SELECT first_seen_day, id, 'investigating', 'open', 'investigating retired; cases replace it',
    now(), 'migration'
FROM alarms WHERE state = 'investigating';
UPDATE alarms SET state = 'open', triage_version = triage_version + 1,
    triage_updated_at = now(), triage_updated_by = 'migration'
WHERE state = 'investigating';
ALTER TABLE alarms DROP CONSTRAINT alarms_state_check;
ALTER TABLE alarms ADD CONSTRAINT alarms_state_check
    CHECK (state IN ('open', 'mitigated', 'accepted_risk', 'false_positive'));
ALTER TABLE alarms DROP CONSTRAINT alarms_check2;
ALTER TABLE alarms ADD CONSTRAINT alarms_note_check
    CHECK (state = 'open' OR (note IS NOT NULL AND length(note) BETWEEN 1 AND 4000));

INSERT INTO console_finding_triage_history (agent_id, rule_set_id, rule_id, from_state, to_state,
    note, changed_at, changed_by)
SELECT agent_id, rule_set_id, rule_id, 'investigating', 'open',
    'investigating retired; cases replace it', now(), 'migration'
FROM console_finding_triage WHERE state = 'investigating';
UPDATE console_finding_triage SET state = 'open', version = version + 1,
    updated_at = now(), updated_by = 'migration'
WHERE state = 'investigating';
ALTER TABLE console_finding_triage DROP CONSTRAINT console_finding_triage_state_check;
ALTER TABLE console_finding_triage ADD CONSTRAINT console_finding_triage_state_check
    CHECK (state IN ('open', 'mitigated', 'accepted_risk', 'false_positive'));
ALTER TABLE console_finding_triage DROP CONSTRAINT console_finding_triage_check;
ALTER TABLE console_finding_triage ADD CONSTRAINT console_finding_triage_note_check
    CHECK (state = 'open' OR (note IS NOT NULL AND length(note) BETWEEN 1 AND 4000));

-- 2. Vulnerability triage, per host x advisory: the key case items use
-- (`agent/advisory`). "Fixed" stays automatic (vulnerabilities.fixed_at).
CREATE TABLE vulnerability_triage (
    agent_id text NOT NULL,
    advisory_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('open', 'mitigated', 'accepted_risk', 'false_positive')),
    assigned_to uuid REFERENCES console_users,
    note text,
    accepted_until timestamptz,
    version bigint NOT NULL CHECK (version > 0),
    updated_at timestamptz NOT NULL,
    updated_by text NOT NULL,
    mitigated_at timestamptz,
    PRIMARY KEY (agent_id, advisory_id),
    FOREIGN KEY (agent_id, advisory_id)
        REFERENCES vulnerabilities (agent_id, advisory_id) ON DELETE CASCADE,
    CHECK (state = 'open' OR (note IS NOT NULL AND length(note) BETWEEN 1 AND 4000)),
    CHECK ((state = 'accepted_risk') = (accepted_until IS NOT NULL))
);
CREATE TABLE vulnerability_triage_history (
    event_id bigserial PRIMARY KEY,
    agent_id text NOT NULL,
    advisory_id text NOT NULL,
    from_state text CHECK (from_state IS NULL
        OR from_state IN ('open', 'mitigated', 'accepted_risk', 'false_positive')),
    to_state text NOT NULL CHECK (to_state IN ('open', 'mitigated', 'accepted_risk', 'false_positive')),
    note text CHECK (note IS NULL OR length(note) BETWEEN 1 AND 4000),
    changed_at timestamptz NOT NULL,
    changed_by text NOT NULL,
    FOREIGN KEY (agent_id, advisory_id)
        REFERENCES vulnerabilities (agent_id, advisory_id) ON DELETE CASCADE
);
CREATE INDEX vulnerability_triage_history_key_idx
    ON vulnerability_triage_history (agent_id, advisory_id, event_id DESC);

-- A fix clears open and mitigated triage, so a vulnerability that comes back
-- (a downgrade) starts open; an unexpired accepted risk or false positive is
-- kept. Runs as its owner: the vulnerability matcher needs no new grants.
CREATE FUNCTION vulnerability_fixed_clears_triage() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    DELETE FROM vulnerability_triage t
    WHERE t.agent_id = NEW.agent_id AND t.advisory_id = NEW.advisory_id
      AND (t.state IN ('open', 'mitigated')
           OR (t.state = 'accepted_risk' AND t.accepted_until <= now()));
    RETURN NEW;
END $$;
CREATE TRIGGER vulnerability_fixed_clears_triage
    AFTER UPDATE OF fixed_at ON vulnerabilities
    FOR EACH ROW WHEN (OLD.fixed_at IS NULL AND NEW.fixed_at IS NOT NULL)
    EXECUTE FUNCTION vulnerability_fixed_clears_triage();
REVOKE ALL ON FUNCTION vulnerability_fixed_clears_triage() FROM PUBLIC;

INSERT INTO console_permissions (permission_id, scope_class)
VALUES ('vulnerabilities.triage', 'agent')
ON CONFLICT (permission_id) DO NOTHING;
INSERT INTO console_role_permissions (role_id, permission_id)
SELECT role_id, 'vulnerabilities.triage' FROM console_role_permissions
WHERE permission_id = 'compliance.triage'
ON CONFLICT DO NOTHING;

GRANT SELECT, INSERT, UPDATE ON vulnerability_triage TO "openvibes-console";
GRANT SELECT, INSERT ON vulnerability_triage_history TO "openvibes-console";
GRANT USAGE ON SEQUENCE vulnerability_triage_history_event_id_seq TO "openvibes-console";
-- Open-vulnerability counts per host leave out triaged ones (mitigated,
-- false positive, unexpired accepted risk): the matcher's recount reads the
-- triage, and the console recounts a host after a triage change.
GRANT SELECT ON vulnerability_triage TO "openvibes-vulns";
GRANT INSERT, UPDATE ON host_vulnerability_counts TO "openvibes-console";
