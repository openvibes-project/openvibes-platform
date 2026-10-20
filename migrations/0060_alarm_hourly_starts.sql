-- OpenVIBES platform schema version 60: per-hour alarm starts (roles plan
-- 2026-10-20 step 5a, ruling 10), for the alarm page's "Last 24 hours"
-- timeline. Ingest adds a new alarm's whole count, or a growing count's
-- difference, to the hour it receives the report; a shrinking or repeated
-- count adds nothing. Not partitioned and no FK to `alarms` (its key
-- includes the partition day); maintenance deletes hours older than 7 days.
CREATE TABLE alarm_hourly_starts (
    alarm_row_id bigint NOT NULL,
    hour timestamptz NOT NULL,
    starts bigint NOT NULL CHECK (starts > 0),
    PRIMARY KEY (alarm_row_id, hour)
);
GRANT SELECT, INSERT, UPDATE ON alarm_hourly_starts TO "openvibes-ingest";
GRANT SELECT ON alarm_hourly_starts TO "openvibes-console";
