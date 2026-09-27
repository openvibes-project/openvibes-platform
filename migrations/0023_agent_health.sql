-- Agent health (protocol P12): the latest report from a heartbeat, the one
-- before it (to tell a total that rose), and when it was written. The
-- ingest and console roles have table-level grants on agents.
ALTER TABLE agents
    ADD COLUMN health jsonb,
    ADD COLUMN health_previous jsonb,
    ADD COLUMN health_at timestamptz;
