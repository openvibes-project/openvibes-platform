-- OpenVIBES platform schema version 4: the ingest role keeps only the rights
-- it uses. It inserts findings, certificates, and token uses but never
-- updates them (current_findings and agents keep UPDATE: upsert, heartbeat).
REVOKE UPDATE ON findings, certificates, token_uses FROM openvibes_ingest;
