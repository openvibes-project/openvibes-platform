-- OpenVIBES platform schema version 16: bounded console enrollment-token
-- administration. The browser API stores only the same secret hash as ingest.
GRANT SELECT, INSERT, UPDATE ON enrollment_tokens TO openvibes_console;
GRANT SELECT ON token_uses TO openvibes_console;
