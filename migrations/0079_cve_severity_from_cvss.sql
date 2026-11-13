-- A CVE's severity comes from its own CVSS base score (#622): 9.0 and up
-- critical, 7.0 important (High), 4.0 moderate (Medium), above 0 low. A
-- distribution's rating (`rated`) applies only without a score, and an
-- advisory naming no CVE keeps its rating. Every view that shows or counts
-- a vulnerability's severity calls these, so they all agree.
CREATE FUNCTION openvibes_severity(score real, rated text) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    RETURN CASE WHEN score >= 9 THEN 'critical'
                WHEN score >= 7 THEN 'important'
                WHEN score >= 4 THEN 'moderate'
                WHEN score > 0 THEN 'low'
                ELSE COALESCE(rated, 'unrated') END;

-- An advisory's severity: the worst of its CVEs', each by
-- openvibes_severity with the advisory's rating as the fallback; the rating
-- itself when it names no CVE.
CREATE FUNCTION openvibes_advisory_severity(advisory text, rated text) RETURNS text
    LANGUAGE sql STABLE PARALLEL SAFE
    RETURN (SELECT (ARRAY['critical','important','moderate','low','unrated'])[
                       min(array_position(ARRAY['critical','important','moderate','low','unrated'],
                                          openvibes_severity(x.cvss_score, rated)))]
            FROM (SELECT 1) one
            LEFT JOIN advisory_cves c ON c.advisory_id = advisory
            LEFT JOIN cve_enrichment x ON x.cve_id = c.cve_id);

-- The console's lists and pages and the vulns service's per-host counts call
-- them; both roles already read advisory_cves and cve_enrichment.
GRANT EXECUTE ON FUNCTION openvibes_severity(real, text), openvibes_advisory_severity(text, text)
    TO "openvibes-console", "openvibes-vulns";
