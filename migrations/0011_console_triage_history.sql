-- OpenVIBES platform schema version 11: retain triage assignments, risk
-- expiry, and detector version in the immutable transition history.
ALTER TABLE console_finding_triage_history
    ADD COLUMN assigned_to uuid REFERENCES console_users,
    ADD COLUMN accepted_until timestamptz,
    ADD COLUMN rule_version bigint;

-- Ingest reopens completed triage in the same transaction as the observation.
GRANT SELECT, UPDATE ON console_finding_triage TO openvibes_ingest;
GRANT INSERT ON console_finding_triage_history TO openvibes_ingest;
GRANT USAGE ON SEQUENCE console_finding_triage_history_event_id_seq TO openvibes_ingest;
