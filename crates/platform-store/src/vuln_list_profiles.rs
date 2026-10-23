//! The Vulnerabilities list's pairs without a fix, counted through host
//! profiles, and the hosts holding one pair for an advisory with both a
//! fixable row and a package without a fix: CTEs of the statement in
//! `vuln_list_sql`.

use crate::vuln_list_sql::HOSTS;

/// `prof`: hosts grouped by release and the package versions they have
/// that a no-fix advisory or a CPE match names (by a fingerprint of the
/// set: count, sum and xor of hashes), counted and masked on each side of
/// the group filter, with one sample host; `pv_adv`: each profile's version
/// pairs (no-fix advisories of the host's release, and CPE matches as
/// `CPE:<cve>:<product>`, never triaged, so open and unassigned) with
/// their package names as `[{name}]`. A host with a fixable row for an
/// advisory also without a fix (`overlap`) holds one pair, the fixable one,
/// while that is unfixed: `dup` counts those hosts (sorted bytewise:
/// 180,000 advisory ids in the database's collation took 0.25 s) per
/// profile, group side
/// and mask (`hostprof` maps hosts to profiles and to `cls`, one profile,
/// side and mask; `profm` counts each class's hosts), and `ded` takes them
/// out of those counts, dropping a class whose hosts all left. Once the
/// fixable row is fixed, a package still without a fix is an open pair of
/// its own. Listing those no-fix pairs per
/// host instead took 28 s with 100 such advisories on the sizing fleet.
// ponytail: a fingerprint collision (two package-version sets with equal
// count, sum and 64-bit xor-hash) would merge two profiles; vanishingly
// unlikely. Profiles scale with distinct affected-package sets: 3 on the
// sizing fleet, up to one per host on a fleet where every host differs.
pub(crate) fn profiles() -> String {
    format!(
        "overlap AS MATERIALIZED (
  SELECT advisory_id FROM fix
  INTERSECT SELECT advisory_id FROM version_vulnerabilities),
hostfp AS MATERIALIZED (
  SELECT hp.agent_id, count(*) AS c, sum(hp.package_version_id) AS s,
         bit_xor(hashint8extended(hp.package_version_id, 0)) AS x
  FROM host_packages hp
  WHERE (($1::boolean AND $9::text IS NULL) OR hp.agent_id IN (SELECT h.agent_id FROM {HOSTS} h))
    AND hp.package_version_id IN (SELECT package_version_id FROM version_vulnerabilities
                                  UNION SELECT package_version_id FROM cpe_findings)
  GROUP BY hp.agent_id),
prof AS MATERIALIZED (
  SELECT row_number() OVER () AS id, h.os_id, h.os_release, f.c, f.s, f.x, min(f.agent_id) AS sample,
         count(*) FILTER (WHERE h.in_group) AS n_in, count(*) FILTER (WHERE NOT h.in_group) AS n_out,
         bit_or(h.mask) FILTER (WHERE h.in_group) AS mask_in, bit_or(h.mask) FILTER (WHERE NOT h.in_group) AS mask_out,
         array_agg(h.agent_id) FILTER (WHERE h.in_group) AS agents
  FROM hostfp f JOIN hosts h ON h.agent_id = f.agent_id
  GROUP BY h.os_id, h.os_release, f.c, f.s, f.x),
pv_adv AS MATERIALIZED (
  SELECT p.id AS prof, vv.advisory_id, NULL::text AS cve, false AS lc, NULL::real AS cvss,
         jsonb_agg(DISTINCT jsonb_build_object('name', vv.package)) AS packages
  FROM prof p JOIN host_packages hp ON hp.agent_id = p.sample
  JOIN version_vulnerabilities vv ON vv.package_version_id = hp.package_version_id
  JOIN advisories a ON a.advisory_id = vv.advisory_id AND a.os_id = p.os_id AND a.os_version = p.os_release
  GROUP BY p.id, vv.advisory_id
  UNION ALL
  SELECT p.id, 'CPE:' || f.cve_id || ':' || f.product, f.cve_id, max(f.confidence) < 80, max(f.cvss),
         jsonb_agg(DISTINCT jsonb_build_object('name', f.package))
  FROM prof p JOIN host_packages hp ON hp.agent_id = p.sample
  JOIN cpe_findings f ON f.package_version_id = hp.package_version_id AND f.os_version = p.os_release
  GROUP BY p.id, f.cve_id, f.product),
hostprof AS MATERIALIZED (
  SELECT f.agent_id, p.id AS prof, h.in_group, h.mask,
         dense_rank() OVER (ORDER BY p.id, h.in_group, h.mask::text) AS cls
  FROM hostfp f JOIN hosts h ON h.agent_id = f.agent_id
  JOIN prof p ON p.os_id = h.os_id AND p.os_release = h.os_release AND p.c = f.c AND p.s = f.s AND p.x = f.x),
dupv AS MATERIALIZED (
  SELECT v.agent_id, v.advisory_id FROM vulnerabilities v
  WHERE v.fixed_at IS NULL AND v.advisory_id = ANY((SELECT array_agg(advisory_id) FROM overlap)::text[])),
dup AS MATERIALIZED (
  SELECT v.advisory_id COLLATE \"C\" AS advisory_id, hp.cls, count(*) AS n
  FROM dupv v JOIN hostprof hp ON hp.agent_id = v.agent_id
  GROUP BY hp.cls, v.advisory_id COLLATE \"C\"),
dpa AS MATERIALIZED (
  SELECT pa.prof, pa.advisory_id FROM pv_adv pa WHERE pa.advisory_id IN (SELECT advisory_id FROM dup)),
profm AS MATERIALIZED (
  SELECT hp.cls, min(hp.prof) AS prof, bool_and(hp.in_group) AS in_group, bit_or(hp.mask) AS mask, count(*) AS n
  FROM hostprof hp GROUP BY hp.cls),
ded AS MATERIALIZED (
  SELECT y.advisory_id, min(y.prof) AS prof, bool_and(y.in_group) AS in_group, bit_or(y.mask) AS mask,
         sum(y.n) AS n
  FROM (SELECT pa.advisory_id, m.cls, m.prof, m.in_group, m.mask, m.n FROM dpa pa JOIN profm m ON m.prof = pa.prof
        UNION ALL
        SELECT d.advisory_id, d.cls, a.prof[d.cls], a.in_group[d.cls], a.mask[d.cls], -d.n
        FROM dup d, (SELECT array_agg(m.prof ORDER BY m.cls) AS prof, array_agg(m.in_group ORDER BY m.cls) AS in_group,
                            array_agg(m.mask ORDER BY m.cls) AS mask FROM profm m) a) y
  GROUP BY y.advisory_id, y.cls
  -- A class whose profile lacks the advisory has only a negative part.
  HAVING sum(y.n) > 0)"
    )
}
