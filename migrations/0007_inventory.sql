-- OpenVIBES platform schema version 7: package inventories for vulnerability
-- management (VM spec 2026-09-25). Distinct package versions are stored once
-- for the whole fleet; hosts link to them.
ALTER TABLE agents
    ADD COLUMN os_id text,
    ADD COLUMN os_version text,
    ADD COLUMN inventory_sha256 bytea CHECK (length(inventory_sha256) = 32),
    ADD COLUMN inventory_at timestamptz;
CREATE TABLE package_versions (
    id bigserial PRIMARY KEY,
    manager text NOT NULL,
    name text NOT NULL,
    epoch integer NOT NULL DEFAULT 0,
    version text NOT NULL,
    release text NOT NULL DEFAULT '',
    arch text NOT NULL DEFAULT '',
    UNIQUE (manager, name, epoch, version, release, arch)
);
CREATE INDEX package_versions_name ON package_versions (name, arch);
CREATE TABLE host_packages (
    agent_id text NOT NULL REFERENCES agents ON DELETE CASCADE,
    package_version_id bigint NOT NULL REFERENCES package_versions,
    PRIMARY KEY (agent_id, package_version_id)
);
CREATE INDEX host_packages_version ON host_packages (package_version_id);
-- Ingest adds versions and replaces a host's links; it never edits either.
GRANT SELECT, INSERT ON package_versions TO openvibes_ingest;
GRANT USAGE ON SEQUENCE package_versions_id_seq TO openvibes_ingest;
GRANT SELECT, INSERT, DELETE ON host_packages TO openvibes_ingest;
