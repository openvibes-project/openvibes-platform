-- OpenVIBES platform schema version 10: CVE enrichment (VM spec §6, §9).
-- CISA KEV (exploited in the wild) and FIRST EPSS (likelihood of
-- exploitation) per CVE; NVD and EUVD columns follow in VM5. KEV and EPSS
-- are sources in feed_sources, checked with their ETag.
CREATE TABLE cve_enrichment (
    cve_id text PRIMARY KEY,
    kev_added date,
    kev_due date,
    kev_ransomware boolean,
    epss real CHECK (epss BETWEEN 0 AND 1),
    epss_percentile real CHECK (epss_percentile BETWEEN 0 AND 1),
    epss_date date
);
CREATE INDEX cve_enrichment_kev ON cve_enrichment (cve_id) WHERE kev_added IS NOT NULL;
ALTER TABLE feed_sources ADD COLUMN etag text;
GRANT SELECT, INSERT, UPDATE, DELETE ON cve_enrichment TO openvibes_vulns;
