-- OpenVIBES platform schema version 14: vulnerabilities without a fix are
-- kept per package version, not per host (the user, 2026-09-26). A Debian
-- server has ~2,700 of them; per host that was ~20 GB per 10,000 hosts,
-- while the fleet shares a few hundred package versions. A host's are
-- those of the versions it has (host_packages).
CREATE TABLE version_vulnerabilities (
    package_version_id bigint NOT NULL REFERENCES package_versions,
    advisory_id text NOT NULL REFERENCES advisories,
    package text NOT NULL,
    first_seen_at timestamptz NOT NULL,
    PRIMARY KEY (package_version_id, advisory_id, package)
);
CREATE INDEX version_vulnerabilities_advisory ON version_vulnerabilities (advisory_id);
GRANT SELECT, INSERT, UPDATE, DELETE, MAINTAIN ON version_vulnerabilities TO openvibes_vulns;
-- Each host's counts, refreshed when the host is matched, so the fleet
-- summary adds numbers instead of scanning millions of rows (10,000 Debian
-- hosts: 3.2 M fixable rows, 27 M no-fix pairs; docs/sizing.md).
CREATE TABLE host_vulnerability_counts (
    agent_id text PRIMARY KEY REFERENCES agents ON DELETE CASCADE,
    no_fix integer NOT NULL,
    critical integer NOT NULL,
    important integer NOT NULL,
    moderate integer NOT NULL,
    low integer NOT NULL,
    unrated integer NOT NULL,
    reboot integer NOT NULL,
    counted_at timestamptz NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON host_vulnerability_counts TO openvibes_vulns;
-- Per-host rows without any fixed version move to the new table at the
-- next match (nothing is deployed yet, so they are simply dropped).
DELETE FROM vulnerabilities v
WHERE NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v.packages) p
                  WHERE p->>'fixed' IS NOT NULL);
