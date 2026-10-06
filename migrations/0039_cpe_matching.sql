-- OpenVIBES platform schema version 39: CPE matching from NVD applicability
-- data (spec 2026-10-06-cpe-matching-design.md). Lower-confidence findings
-- that no distribution advisory covers, kept apart from `vulnerabilities`
-- so the existing counts keep meaning "a distribution says so".

-- Which upstream versions of which product a CVE affects (NVD
-- `configurations`), kept only for products installed packages could be.
CREATE TABLE cve_applicability (
    cve_id text NOT NULL,
    vendor text NOT NULL,
    product text NOT NULL,
    introduced text,
    fixed text,
    last_affected text,
    cvss real CHECK (cvss BETWEEN 0 AND 10),
    -- Fedora releases NVD itself lists as affected (`o:fedoraproject:fedora:N`).
    fedora text[] NOT NULL DEFAULT '{}'
);
CREATE INDEX cve_applicability_product ON cve_applicability (product);
CREATE INDEX cve_applicability_cve ON cve_applicability (cve_id);

-- The products being kept. A product that appears later restarts the
-- crawl of NVD (its older CVEs were dropped when read).
CREATE TABLE cve_applicability_products (
    product text PRIMARY KEY
);

-- Findings: one installed package version in an affected range, per
-- release (advisories differ by release), keeping when first seen.
CREATE TABLE cpe_findings (
    package_version_id bigint NOT NULL REFERENCES package_versions ON DELETE CASCADE,
    os_version text NOT NULL,
    cve_id text NOT NULL,
    product text NOT NULL,
    package text NOT NULL,
    installed text NOT NULL,
    range_text text NOT NULL,
    confidence smallint NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    basis text NOT NULL,
    cvss real,
    first_seen_at timestamptz NOT NULL,
    PRIMARY KEY (package_version_id, os_version, cve_id, product)
);
CREATE INDEX cpe_findings_cve ON cpe_findings (cve_id);

GRANT SELECT, INSERT, UPDATE, DELETE
    ON cve_applicability, cve_applicability_products, cpe_findings TO "openvibes-vulns";
GRANT SELECT ON cpe_findings TO "openvibes-console";
