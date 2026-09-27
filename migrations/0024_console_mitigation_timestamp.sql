-- OpenVIBES platform schema version 24: preserve the transition time into
-- mitigation across later edits to the note or assignee.
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
