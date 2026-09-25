-- OpenVIBES platform schema version 9: the running kernel (protocol P9), so
-- a kernel fix that is installed but not yet booted stays open, flagged
-- "fix installed, reboot needed".
ALTER TABLE agents ADD COLUMN running_kernel text;
ALTER TABLE vulnerabilities ADD COLUMN reboot_needed boolean NOT NULL DEFAULT false;
