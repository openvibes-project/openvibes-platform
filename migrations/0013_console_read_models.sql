-- OpenVIBES platform schema version 13: keep latest-finding display data
-- independent of the retention window for partitioned history.
ALTER TABLE current_findings
    ADD COLUMN last_observed_day date,
    ADD COLUMN scan_id text,
    ADD COLUMN confidence smallint,
    ADD COLUMN message text,
    ADD COLUMN evidence text[],
    ADD COLUMN received_at timestamptz,
    ADD COLUMN origin text,
    ADD COLUMN authenticated boolean;

UPDATE current_findings AS cf
SET last_observed_day = event.observed_day,
    scan_id = event.scan_id,
    confidence = event.confidence,
    message = event.message,
    evidence = event.evidence,
    received_at = event.received_at,
    origin = event.origin,
    authenticated = event.authenticated
FROM findings AS event
WHERE event.finding_id = cf.last_finding_id
  AND event.agent_id = cf.agent_id
  AND event.rule_set_id = cf.rule_set_id
  AND event.rule_id = cf.rule_id
  AND event.observed_at = cf.last_observed_at;

-- The latest event can have aged out with its partition. Such a current row
-- has no retained observation to display and must age out with it.
DELETE FROM current_findings WHERE last_observed_day IS NULL;

ALTER TABLE current_findings
    ALTER COLUMN last_observed_day SET NOT NULL,
    ALTER COLUMN scan_id SET NOT NULL,
    ALTER COLUMN confidence SET NOT NULL,
    ALTER COLUMN message SET NOT NULL,
    ALTER COLUMN evidence SET NOT NULL,
    ALTER COLUMN received_at SET NOT NULL,
    ALTER COLUMN origin SET NOT NULL,
    ALTER COLUMN authenticated SET NOT NULL;
ALTER TABLE current_findings
    ADD CONSTRAINT current_findings_confidence_check CHECK (confidence BETWEEN 0 AND 100),
    ADD CONSTRAINT current_findings_origin_check CHECK (origin IN ('online', 'import')),
    ADD CONSTRAINT current_findings_severity_check
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'));
ALTER TABLE findings
    ADD CONSTRAINT findings_severity_check
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'));

CREATE INDEX agents_console_last_seen_idx
    ON agents (last_seen_at DESC NULLS LAST, agent_id ASC);
CREATE INDEX current_findings_console_latest_idx
    ON current_findings (last_observed_at DESC, agent_id ASC, rule_set_id ASC, rule_id ASC);
CREATE INDEX findings_console_history_idx
    ON findings (observed_at DESC, observed_day DESC, finding_id ASC);
