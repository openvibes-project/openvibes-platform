-- OpenVIBES platform schema version 58: each host's critical advisories as
-- the Vulnerabilities list shows them by default, for the Hosts list's
-- "critical" count (roles plan 2026-10-20, Task 7): one per advisory,
-- fixable or without a fix, reboot pending or not, mapped at confidence 80
-- or more (vulns/confidence.rs: a known distribution's advisory, or a
-- package without a fix) and with this host's triage open. The host page's
-- summary counts the same rows. A derived count, kept beside
-- host_vulnerability_counts (whose `critical`, fixable with no reboot
-- pending, still feeds the fleet summary and its history) and recounted
-- with it by platform-store's `refresh_counts`; hosts without a row have 0.
CREATE TABLE host_listed_critical AS
SELECT y.agent_id, count(DISTINCT y.advisory_id)::int AS critical
FROM (SELECT v.agent_id, v.advisory_id
      FROM vulnerabilities v JOIN advisories a ON a.advisory_id = v.advisory_id
      WHERE v.fixed_at IS NULL AND a.severity = 'critical'
        AND (split_part(a.source, '-', 1) IN ('fedora', 'debian', 'ubuntu', 'rocky', 'almalinux')
             OR (jsonb_typeof(v.packages) = 'array' AND jsonb_array_length(v.packages) > 0
                 AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v.packages) p
                                 WHERE p ? 'fixed' AND jsonb_typeof(p->'fixed') IS DISTINCT FROM 'null')))
      UNION ALL
      SELECT hp.agent_id, vv.advisory_id
      FROM host_packages hp
      JOIN version_vulnerabilities vv ON vv.package_version_id = hp.package_version_id
      JOIN advisories a ON a.advisory_id = vv.advisory_id
      WHERE a.severity = 'critical') y
WHERE NOT EXISTS (SELECT 1 FROM vulnerability_triage t
                  WHERE t.agent_id = y.agent_id AND t.advisory_id = y.advisory_id
                    AND t.state <> 'open')
GROUP BY y.agent_id;
ALTER TABLE host_listed_critical
    ALTER COLUMN agent_id SET NOT NULL,
    ALTER COLUMN critical SET NOT NULL,
    ADD PRIMARY KEY (agent_id),
    ADD FOREIGN KEY (agent_id) REFERENCES agents ON DELETE CASCADE;
GRANT SELECT, INSERT, UPDATE, DELETE ON host_listed_critical TO "openvibes-vulns";
GRANT SELECT, INSERT, UPDATE, DELETE ON host_listed_critical TO "openvibes-console";
