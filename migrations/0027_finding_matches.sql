-- OpenVIBES platform schema version 27: finding changes (protocol P13).
-- A match is open while ended_at is NULL. source says how the agent
-- reports: 'scan' (every scan, before P13) or 'changes' (P13).
ALTER TABLE current_findings
    ADD COLUMN ended_at timestamptz,
    ADD COLUMN end_approximate boolean NOT NULL DEFAULT false,
    ADD COLUMN source text NOT NULL DEFAULT 'scan'
        CHECK (source IN ('scan', 'changes'));
-- The digest of the agent's open P13 matches the platform acknowledged.
ALTER TABLE agents ADD COLUMN match_sha256 bytea;
CREATE INDEX current_findings_open_changes
    ON current_findings (agent_id) WHERE source = 'changes' AND ended_at IS NULL;
