-- OpenVIBES platform schema version 20: retain triage assignments, risk
-- expiry, and detector version in the immutable transition history.
ALTER TABLE console_finding_triage_history
    ADD COLUMN assigned_to uuid REFERENCES console_users,
    ADD COLUMN accepted_until timestamptz,
    ADD COLUMN rule_version bigint;

-- Ingest reopens completed triage in the same transaction as the observation.
GRANT SELECT, UPDATE ON console_finding_triage TO "openvibes-ingest";
GRANT INSERT ON console_finding_triage_history TO "openvibes-ingest";
GRANT USAGE ON SEQUENCE console_finding_triage_history_event_id_seq TO "openvibes-ingest";

-- Preserve the transition time into mitigation across later note/assignee edits.
ALTER TABLE console_finding_triage
    ADD COLUMN mitigated_at timestamptz;

UPDATE console_finding_triage t
SET mitigated_at = COALESCE(
    (SELECT h.changed_at
     FROM console_finding_triage_history h
     WHERE h.agent_id = t.agent_id
       AND h.rule_set_id = t.rule_set_id
       AND h.rule_id = t.rule_id
       AND h.to_state = 'mitigated'
       AND h.from_state IS DISTINCT FROM 'mitigated'
     ORDER BY h.event_id DESC
     LIMIT 1),
    t.updated_at
)
WHERE t.state = 'mitigated';
