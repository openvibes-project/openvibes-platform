-- OpenVIBES platform schema version 3: the latest OS-reported hostname from
-- authenticated heartbeats. An operator label only: spoofable, never
-- identity or authorisation input.
ALTER TABLE agents ADD COLUMN hostname text;
CREATE INDEX agents_hostname_idx ON agents (hostname);
