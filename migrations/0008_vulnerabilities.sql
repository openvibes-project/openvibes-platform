-- OpenVIBES platform schema version 8: vulnerability management (VM spec
-- 2026-09-25). Advisories from feeds, the vulnerabilities they open on
-- hosts (kept after they are fixed), and each feed's state.
CREATE TABLE advisories (
    advisory_id text PRIMARY KEY,
    source text NOT NULL,
    os_id text NOT NULL,
    os_version text NOT NULL,
    severity text NOT NULL
        CHECK (severity IN ('critical', 'important', 'moderate', 'low', 'unrated')),
    title text NOT NULL,
    issued_at timestamptz,
    updated_at timestamptz,
    url text NOT NULL
);
CREATE INDEX advisories_release ON advisories (os_id, os_version);
CREATE TABLE advisory_cves (
    advisory_id text NOT NULL REFERENCES advisories ON DELETE CASCADE,
    cve_id text NOT NULL,
    PRIMARY KEY (advisory_id, cve_id)
);
CREATE INDEX advisory_cves_cve ON advisory_cves (cve_id);
CREATE TABLE advisory_packages (
    advisory_id text NOT NULL REFERENCES advisories ON DELETE CASCADE,
    name text NOT NULL,
    arch text NOT NULL,
    epoch integer NOT NULL DEFAULT 0,
    version text NOT NULL,
    release text NOT NULL DEFAULT '',
    PRIMARY KEY (advisory_id, name, arch)
);
CREATE INDEX advisory_packages_name ON advisory_packages (name);
CREATE TABLE vulnerabilities (
    agent_id text NOT NULL REFERENCES agents ON DELETE CASCADE,
    advisory_id text NOT NULL REFERENCES advisories,
    packages jsonb NOT NULL,
    first_seen_at timestamptz NOT NULL,
    fixed_at timestamptz,
    last_evaluated_at timestamptz NOT NULL,
    PRIMARY KEY (agent_id, advisory_id)
);
CREATE INDEX vulnerabilities_open ON vulnerabilities (advisory_id) WHERE fixed_at IS NULL;
CREATE TABLE feed_sources (
    source text PRIMARY KEY,
    os_id text NOT NULL,
    os_version text NOT NULL,
    arch text NOT NULL,
    last_checked_at timestamptz,
    last_changed_at timestamptz,
    content_sha256 bytea CHECK (length(content_sha256) = 32),
    advisories integer NOT NULL DEFAULT 0,
    last_error text
);
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openvibes_vulns') THEN
        CREATE ROLE openvibes_vulns LOGIN;
    END IF;
-- Roles are cluster-wide: parallel migrations (tests) can race on creation.
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE
    ON advisories, advisory_cves, advisory_packages, vulnerabilities, feed_sources
    TO openvibes_vulns;
GRANT SELECT ON agents, package_versions, host_packages, schema_version TO openvibes_vulns;
