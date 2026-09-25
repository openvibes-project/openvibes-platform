-- OpenVIBES platform schema version 12: openvibes_vulns may ANALYZE the
-- tables it bulk-loads, so the matching queries right after a feed import
-- are planned with current statistics (scale check, docs/sizing.md).
-- MAINTAIN needs PostgreSQL 17 or later.
GRANT MAINTAIN ON advisories, advisory_cves, advisory_packages, vulnerabilities, cve_enrichment
    TO openvibes_vulns;
