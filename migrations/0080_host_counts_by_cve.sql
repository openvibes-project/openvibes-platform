-- openvibes: needs-backup (recounts every host by the new rule)
-- Per-host counts count CVEs, as the Vulnerabilities list does (#590):
-- `host_vulnerability_counts` holds each host's open CVEs (or advisories
-- naming none) per severity, and now also its exploited ones (KEV or EUVD),
-- stored like the others instead of counted per advisory on every request.
ALTER TABLE host_vulnerability_counts ADD COLUMN exploited integer NOT NULL DEFAULT 0;

-- A CVE's severity follows its CVSS score (#622) and its exploited flag
-- follows KEV and EUVD, all in `cve_enrichment`, which changes without a
-- host re-match. One row records when it last changed; the vulns service
-- recounts hosts counted before that.
CREATE TABLE enrichment_changed (
    only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    changed_at timestamptz NOT NULL
);
INSERT INTO enrichment_changed (changed_at) VALUES (now());

CREATE FUNCTION enrichment_changed_mark() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    UPDATE enrichment_changed SET changed_at = now() WHERE only_row;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION enrichment_changed_mark() FROM PUBLIC;

CREATE TRIGGER cve_enrichment_changed
    AFTER INSERT OR UPDATE OR DELETE ON cve_enrichment
    FOR EACH STATEMENT EXECUTE FUNCTION enrichment_changed_mark();

GRANT SELECT ON enrichment_changed TO "openvibes-vulns", "openvibes-console";

-- Every existing host is recounted by the new rule on the vulns service's
-- next check (its counts are older than the row above).
UPDATE host_vulnerability_counts SET counted_at = '-infinity' WHERE counted_at > '-infinity';
