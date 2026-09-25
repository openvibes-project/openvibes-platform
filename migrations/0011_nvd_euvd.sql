-- OpenVIBES platform schema version 11: NVD and EUVD enrichment (VM spec
-- §6, §9). NVD data is kept only for CVEs advisories name; EUVD's
-- exploited list is kept whole. feed_sources.cursor is NVD's sync point.
ALTER TABLE cve_enrichment
    ADD COLUMN cvss_score real CHECK (cvss_score BETWEEN 0 AND 10),
    ADD COLUMN cvss_version text,
    ADD COLUMN cvss_vector text,
    ADD COLUMN cwe text[],
    ADD COLUMN description text,
    ADD COLUMN nvd_modified_at timestamptz,
    ADD COLUMN nvd_checked_at timestamptz,
    ADD COLUMN euvd_id text,
    ADD COLUMN euvd_exploited boolean,
    ADD COLUMN euvd_exploited_since date;
CREATE INDEX cve_enrichment_euvd ON cve_enrichment (cve_id) WHERE euvd_exploited;
ALTER TABLE feed_sources ADD COLUMN cursor timestamptz;
