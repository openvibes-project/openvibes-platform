//! The SQL of the Vulnerabilities list's one statement (step 5b rulings
//! 2–6). Pairs in reach are counted into a small `cube`, one row per
//! advisory, triage state, assignee, group-filter side and confidence side:
//! fixable pairs from `vulnerabilities` directly, pairs with no fix and CPE
//! matches through host "profiles" (hosts with the same affected package
//! versions), so the 27 M no-fix pairs of 10,000 Debian hosts are never
//! expanded one by one. The cube is keyed by CVE (`keyed`), folded into one
//! row per key (`r`), and every filter, count and the page read `r`. Only
//! fixed internal strings are formatted in; every value is bound.
//!
//! Parameters: `$1` global scope, `$2` scope group ids, `$3` search, `$4`
//! state (NULL for all), `$5` severity, `$6` signal, `$7` package, `$8`
//! group, `$9` host, `$10` advisory, `$11` assignee user id (text), `$12`
//! unassigned, `$13` today, `$14` limit, `$15` offset.

use crate::vuln_list::VulnSort;

/// One filter whose own condition the counts of its values leave out. The
/// host filter narrows the pairs themselves; the group filter picks the
/// `grp` side of `r`, and the lower-confidence signal its `lc` side.
#[derive(Clone, Copy, PartialEq)]
enum Facet {
    State,
    Assignee,
    Severity,
    Signal,
    Package,
    Advisory,
}

const FACETS: [Facet; 4] = [
    Facet::Severity,
    Facet::Signal,
    Facet::Package,
    Facet::Advisory,
];

/// The `r` rows the page shows: the chosen confidence and group sides.
const MAIN: &str =
    "r.lc = ($6::text IS NOT DISTINCT FROM 'lowconf') AND r.grp = ($8::text IS NOT NULL)";

/// Severities, most severe first; `r.sev` is a position in it.
const SEVERITIES: &str = "ARRAY['critical','important','moderate','low','unrated']";

/// A row filter over an `r` row.
fn filter(facet: Facet) -> &'static str {
    match facet {
        Facet::Severity => {
            "($5::text IS NULL OR r.sev = array_position(ARRAY['critical','important','moderate','low','unrated'], $5))"
        }
        Facet::Signal => {
            "($6::text IS NULL OR $6 = 'lowconf' OR ($6 = 'exploited' AND r.exploited)
              OR ($6 = 'due30' AND r.kev_due <= $13::date + 30) OR ($6 = 'nofix' AND NOT r.fix)
              OR ($6 = 'reboot' AND r.reboot))"
        }
        Facet::Package => "($7::text IS NULL OR $7 = ANY(r.names))",
        Facet::Advisory => "($10::text IS NULL OR $10 = ANY(r.advisories))",
        Facet::State | Facet::Assignee => unreachable!("pair filters are in `except`"),
    }
}

/// Every chosen filter and the search except those of `skip`. State and
/// assignee hold together on one pair: `m_sa` (both), `m_a` (assignee
/// only), `m_s` (state only).
fn except(skip: &[Facet]) -> String {
    let pair = match (
        skip.contains(&Facet::State),
        skip.contains(&Facet::Assignee),
    ) {
        (false, false) => "r.m_sa",
        (true, false) => "r.m_a",
        (false, true) => "r.m_s",
        (true, true) => "true",
    };
    let search = "($3::text IS NULL OR strpos(lower(r.key), lower($3)) > 0
      OR strpos(lower(r.title), lower($3)) > 0
      OR EXISTS (SELECT 1 FROM unnest(r.advisories || r.names) s WHERE strpos(lower(s), lower($3)) > 0))";
    FACETS
        .iter()
        .filter(|f| !skip.contains(f))
        .map(|f| filter(*f))
        .chain([pair, search])
        .collect::<Vec<_>>()
        .join(" AND ")
}

/// A pair's state is one of the filter's; NULL `$4` is every state.
const STATE_OK: &str = "($4::text IS NULL OR c.state = $4)";
/// A pair's assignee matches the Assignee filter.
const ASSIGNEE_OK: &str = "(($11::text IS NULL AND NOT $12::boolean) OR ($12 AND c.assignee IS NULL) OR c.assignee = $11::text::uuid)";

/// A fixable pair's state: fixed is `resolved`; open, or an accepted risk
/// expired by `$13`, is `open` (over `v` and its triage `t`).
const PAIR_STATE: &str = "CASE WHEN v.fixed_at IS NOT NULL THEN 'resolved'
              WHEN t.state = 'accepted_risk' AND t.accepted_until <= ($13::date)::timestamp AT TIME ZONE 'UTC'
                THEN 'open'
              ELSE t.state END";

/// A fixable pair mapped below confidence 80 (`vulns/confidence.rs`): an
/// advisory `a` from an unknown feed (every fixable pair has a fix).
const LOW_CONFIDENCE: &str =
    "split_part(a.source, '-', 1) NOT IN ('fedora', 'debian', 'ubuntu', 'rocky', 'almalinux')";

/// The agents in the scope (`$1`, `$2`, as the Alarms list) and the host
/// filter (`$9`), from the stored membership: `in_group` (the group filter
/// `$8` holds) and `mask` (a bit per `glist` group). A grouped subquery,
/// written in place rather than read from a CTE, so the pair scans that
/// join it can run in parallel workers, and never pulled up, so its
/// columns are worked out once per agent. The group ids are read from the
/// table each time (not from `glist`): a CTE would keep the scans serial.
const HOSTS: &str = "(SELECT a.agent_id, a.os_id, a.os_release,
         $8::text IS NULL OR COALESCE(bool_or(g.asset_group_id::text = lower($8)), false) AS in_group,
         COALESCE(bit_or(rpad(lpad('1', array_position((SELECT COALESCE(array_agg(DISTINCT asset_group_id::text), '{}') FROM console_host_group_membership), g.asset_group_id::text), '0'),
                              cardinality((SELECT COALESCE(array_agg(DISTINCT asset_group_id::text), '{}') FROM console_host_group_membership)), '0')::varbit),
                  repeat('0', cardinality((SELECT COALESCE(array_agg(DISTINCT asset_group_id::text), '{}') FROM console_host_group_membership)))::varbit) AS mask
  FROM agents a LEFT JOIN console_host_group_membership g ON g.agent_id = a.agent_id
  WHERE ($1::boolean OR (a.status <> 'imported' AND EXISTS (
          SELECT 1 FROM console_host_group_membership m
          WHERE m.agent_id = a.agent_id AND m.asset_group_id::text = ANY($2::text[]))))
    AND ($9::text IS NULL OR a.agent_id = $9)
  GROUP BY a.agent_id)";

/// `glist`: the ids of groups holding a host, in mask bit order; `hosts`:
/// [`HOSTS`] materialised for the small joins.
fn hosts() -> String {
    format!(
        "glist AS MATERIALIZED (
  SELECT COALESCE(array_agg(DISTINCT asset_group_id::text), '{{}}') AS ids FROM console_host_group_membership),
hosts AS MATERIALIZED (SELECT * FROM {HOSTS} h)"
    )
}

/// `fix`: the fixable pairs in reach per advisory, state and assignee
/// (triage is joined, most pairs have none), counted, masked and
/// reboot-flagged per group side, in parallel workers; `apnames`: the
/// package names (and fixed versions) of those advisories installed on a
/// host in reach. Grouping the pairs by their package list instead cost
/// 2.3–6 s (a jsonb key that spills or runs in one process).
fn fixable() -> String {
    let side = |(cond, name): (&str, &str)| {
        format!(
            "count(*) FILTER (WHERE {cond}) AS n_{name}, bit_or(h.mask) FILTER (WHERE {cond}) AS m_{name},
         COALESCE(bool_or(v.fixed_at IS NULL AND v.reboot_needed) FILTER (WHERE {cond}), false) AS r_{name}"
        )
    };
    let [inside, outside] = [("h.in_group", "in"), ("NOT h.in_group", "out")].map(side);
    format!(
        "fix AS MATERIALIZED (
  SELECT v.advisory_id, COALESCE({PAIR_STATE}, 'open') AS state, t.assigned_to AS assignee, {inside}, {outside}
  FROM vulnerabilities v JOIN {HOSTS} h ON h.agent_id = v.agent_id
  LEFT JOIN vulnerability_triage t ON t.agent_id = v.agent_id AND t.advisory_id = v.advisory_id
  GROUP BY 1, 2, 3),
apnames AS MATERIALIZED (
  SELECT DISTINCT ap.advisory_id, ap.name, ap.fixed
  FROM (SELECT DISTINCT advisory_id FROM fix) f
  JOIN advisory_packages ap ON ap.advisory_id = f.advisory_id
  WHERE EXISTS (SELECT 1 FROM package_versions pv JOIN host_packages hp ON hp.package_version_id = pv.id
                WHERE pv.name = ap.name AND hp.agent_id IN (SELECT agent_id FROM hosts))
     OR EXISTS (SELECT 1 FROM package_versions pv JOIN host_packages hp ON hp.package_version_id = pv.id
                WHERE pv.source = ap.name AND hp.agent_id IN (SELECT agent_id FROM hosts)))"
    )
}

/// `prof`: hosts grouped by release and the package versions they have
/// that a no-fix advisory or a CPE match names (by a fingerprint of the
/// set: count, sum and xor of hashes), counted and masked on each side of
/// the group filter, with one sample host; `pv_adv`: each profile's version
/// pairs (no-fix advisories of the host's release, and CPE matches as
/// `CPE:<cve>:<product>`, never triaged, so open and unassigned) with
/// their package names as `[{name}]`. A host with a fixable row for an
/// advisory also without a fix (`overlap`) holds one pair: the fixable one;
/// those advisories' no-fix pairs are listed per host (`vx`) without it.
// ponytail: a fingerprint collision (two package-version sets with equal
// count, sum and 64-bit xor-hash) would merge two profiles; vanishingly
// unlikely. Profiles scale with distinct affected-package sets: 3 on the
// sizing fleet, up to one per host on a fleet where every host differs.
fn profiles() -> String {
    format!(
        "overlap AS MATERIALIZED (
  SELECT advisory_id FROM fix
  INTERSECT SELECT advisory_id FROM version_vulnerabilities),
vx AS MATERIALIZED (
  SELECT h.agent_id, vv.advisory_id, h.in_group, h.mask,
         jsonb_agg(DISTINCT jsonb_build_object('name', vv.package)) AS packages
  FROM overlap b JOIN version_vulnerabilities vv ON vv.advisory_id = b.advisory_id
  JOIN advisories a ON a.advisory_id = vv.advisory_id
  JOIN host_packages hp ON hp.package_version_id = vv.package_version_id
  JOIN hosts h ON h.agent_id = hp.agent_id AND h.os_id = a.os_id AND h.os_release = a.os_version
  WHERE NOT EXISTS (SELECT 1 FROM vulnerabilities v WHERE v.agent_id = h.agent_id AND v.advisory_id = vv.advisory_id)
  GROUP BY h.agent_id, vv.advisory_id, h.in_group, h.mask),
hostfp AS (
  SELECT hp.agent_id, count(*) AS c, sum(hp.package_version_id) AS s,
         bit_xor(hashint8extended(hp.package_version_id, 0)) AS x
  FROM host_packages hp
  WHERE (($1::boolean AND $9::text IS NULL) OR hp.agent_id IN (SELECT h.agent_id FROM {HOSTS} h))
    AND hp.package_version_id IN (SELECT package_version_id FROM version_vulnerabilities
                                  UNION SELECT package_version_id FROM cpe_findings)
  GROUP BY hp.agent_id),
prof AS MATERIALIZED (
  SELECT row_number() OVER () AS id, h.os_id, h.os_release, min(f.agent_id) AS sample,
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
  WHERE vv.advisory_id NOT IN (SELECT advisory_id FROM overlap)
  GROUP BY p.id, vv.advisory_id
  UNION ALL
  SELECT p.id, 'CPE:' || f.cve_id || ':' || f.product, f.cve_id, max(f.confidence) < 80, max(f.cvss),
         jsonb_agg(DISTINCT jsonb_build_object('name', f.package))
  FROM prof p JOIN host_packages hp ON hp.agent_id = p.sample
  JOIN cpe_findings f ON f.package_version_id = hp.package_version_id AND f.os_version = p.os_release
  GROUP BY p.id, f.cve_id, f.product)"
    )
}

/// `cube`: pairs counted per advisory, state, assignee, group side,
/// confidence side and package list — a few thousand rows; `keyed`: each
/// under every CVE its advisory names (or the advisory id), once on the
/// all-groups side (`grp` false) and, with a group filter, once more on the
/// group's side.
fn cube() -> String {
    format!(
        "cube AS MATERIALIZED (
  SELECT f.advisory_id, NULL::text AS cve, NULL::real AS cvss, f.state, f.assignee, s.in_group,
         {LOW_CONFIDENCE} AS lc, NULL::jsonb AS packages, s.n, s.mask, s.reboot, true AS fix
  FROM fix f JOIN advisories a ON a.advisory_id = f.advisory_id
  CROSS JOIN LATERAL (VALUES (true, f.n_in, f.m_in, f.r_in), (false, f.n_out, f.m_out, f.r_out))
             s(in_group, n, mask, reboot)
  WHERE s.n > 0
  UNION ALL
  SELECT pa.advisory_id, pa.cve, max(pa.cvss), 'open', NULL::uuid, s.in_group, pa.lc, pa.packages,
         sum(s.n), bit_or(s.mask), false, false
  FROM pv_adv pa JOIN prof p ON p.id = pa.prof
  CROSS JOIN LATERAL (VALUES (true, p.n_in, p.mask_in), (false, p.n_out, p.mask_out)) s(in_group, n, mask)
  WHERE s.n > 0
  GROUP BY pa.advisory_id, pa.cve, s.in_group, pa.lc, pa.packages
  UNION ALL
  SELECT x.advisory_id, NULL, NULL, 'open', NULL, x.in_group, false, x.packages, count(*), bit_or(x.mask), false, false
  FROM vx x GROUP BY x.advisory_id, x.in_group, x.packages),
keyed AS MATERIALIZED (
  SELECT COALESCE(c.cve, ac.cve_id, c.advisory_id) AS key, gs.grp, c.*
  FROM cube c LEFT JOIN advisory_cves ac ON c.cve IS NULL AND ac.advisory_id = c.advisory_id
  CROSS JOIN LATERAL (SELECT false AS grp UNION ALL SELECT true WHERE $8::text IS NOT NULL AND c.in_group) gs)"
    )
}

/// `kadv`: per key, side and covering advisory, its pairs; `kpers`: per
/// key, side and assignee, whether a pair in the chosen state has them and
/// whether an open one does; `knames`: per key and side, the package names
/// and fixed versions; `r`: one row per key and side, with the advisory
/// facts (worst severity, the title of the advisory with the most pairs)
/// and the CVE's enrichment.
fn rows() -> String {
    format!(
        "kadv AS MATERIALIZED (
  SELECT c.key, c.lc, c.grp, c.advisory_id, max(c.cvss) AS cvss, sum(c.n) AS n,
         COALESCE(sum(c.n) FILTER (WHERE c.state = 'open'), 0) AS open,
         bool_or({STATE_OK} AND {ASSIGNEE_OK}) AS m_sa, bool_or({ASSIGNEE_OK}) AS m_a, bool_or({STATE_OK}) AS m_s,
         bool_or(c.state = 'open' AND {ASSIGNEE_OK}) AS st_open,
         bool_or(c.state = 'mitigated' AND {ASSIGNEE_OK}) AS st_mitigated,
         bool_or(c.state = 'accepted_risk' AND {ASSIGNEE_OK}) AS st_accepted_risk,
         bool_or(c.state = 'false_positive' AND {ASSIGNEE_OK}) AS st_false_positive,
         bool_or(c.state = 'resolved' AND {ASSIGNEE_OK}) AS st_resolved,
         bool_or(c.assignee IS NULL AND {STATE_OK}) AS un,
         bit_or(c.mask) FILTER (WHERE {STATE_OK} AND {ASSIGNEE_OK}) AS mask,
         bool_or(c.reboot) AS reboot, bool_or(c.fix) AS fix
  FROM keyed c GROUP BY c.key, c.lc, c.grp, c.advisory_id),
kpers AS MATERIALIZED (
  SELECT c.key, c.lc, c.grp, c.assignee, bool_or({STATE_OK}) AS s_ok, bool_or(c.state = 'open') AS open
  FROM keyed c WHERE c.assignee IS NOT NULL GROUP BY c.key, c.lc, c.grp, c.assignee),
knames AS MATERIALIZED (
  SELECT x.key, x.lc, x.grp, array_agg(DISTINCT x.name ORDER BY x.name) AS names,
         array_agg(DISTINCT x.fixed) FILTER (WHERE x.fixed IS NOT NULL) AS fixed
  FROM (SELECT c.key, c.lc, c.grp, p ->> 'name' AS name, NULL::text AS fixed
        FROM keyed c CROSS JOIN jsonb_array_elements(c.packages) p WHERE c.packages IS NOT NULL
        UNION ALL
        SELECT ka.key, ka.lc, ka.grp, n.name, n.fixed FROM kadv ka JOIN apnames n ON n.advisory_id = ka.advisory_id
        WHERE ka.fix) x
  WHERE x.name IS NOT NULL GROUP BY x.key, x.lc, x.grp),
r AS MATERIALIZED (
  SELECT k.*, COALESCE(o.people, 0) AS people, o.person, COALESCE(n.names, '{{}}') AS names, COALESCE(n.fixed, '{{}}') AS fixed,
         COALESCE(k.title0, x.description, k.key) AS title,
         COALESCE(x.kev_added IS NOT NULL OR x.euvd_exploited, false) AS exploited, x.kev_due,
         COALESCE(x.cvss_score, k.cvss0) AS cvss, x.epss, x.epss_percentile AS pct
  FROM (SELECT ka.key, ka.lc, ka.grp, array_agg(ka.advisory_id ORDER BY ka.advisory_id) AS advisories,
               (array_agg(a.title ORDER BY ka.n DESC, ka.advisory_id) FILTER (WHERE a.title IS NOT NULL))[1] AS title0,
               min(array_position({SEVERITIES}, COALESCE(a.severity,
                   CASE WHEN COALESCE(x.cvss_score, ka.cvss) >= 9 THEN 'critical'
                        WHEN COALESCE(x.cvss_score, ka.cvss) >= 7 THEN 'important'
                        WHEN COALESCE(x.cvss_score, ka.cvss) >= 4 THEN 'moderate'
                        WHEN COALESCE(x.cvss_score, ka.cvss) > 0 THEN 'low' ELSE 'unrated' END))) AS sev,
               max(ka.cvss) AS cvss0, sum(ka.n)::bigint AS total, sum(ka.open)::bigint AS open,
               bool_or(ka.m_sa) AS m_sa, bool_or(ka.m_a) AS m_a, bool_or(ka.m_s) AS m_s,
               bool_or(ka.st_open) AS st_open, bool_or(ka.st_mitigated) AS st_mitigated,
               bool_or(ka.st_accepted_risk) AS st_accepted_risk, bool_or(ka.st_false_positive) AS st_false_positive,
               bool_or(ka.st_resolved) AS st_resolved, bool_or(ka.un) AS un, bit_or(ka.mask) AS mask,
               bool_or(ka.reboot) AS reboot, bool_or(ka.fix) AS fix
        FROM kadv ka LEFT JOIN advisories a ON a.advisory_id = ka.advisory_id
        LEFT JOIN cve_enrichment x ON x.cve_id = ka.key
        GROUP BY ka.key, ka.lc, ka.grp) k
  LEFT JOIN knames n ON n.key = k.key AND n.lc = k.lc AND n.grp = k.grp
  LEFT JOIN (SELECT kp.key, kp.lc, kp.grp, count(*) AS people, min(kp.assignee::text) AS person
             FROM kpers kp WHERE kp.open GROUP BY kp.key, kp.lc, kp.grp) o
    ON o.key = k.key AND o.lc = k.lc AND o.grp = k.grp
  LEFT JOIN cve_enrichment x ON x.cve_id = k.key)"
    )
}

/// CTE `counts`: one JSON object of every facet's values, each with the
/// other filters applied. Group, package and person values come from `r`,
/// which holds only pairs in reach; the chosen group is added with 0 when
/// the scope reaches it, the chosen package when a pair in reach names it.
fn counts() -> String {
    let state = except(&[Facet::State]);
    let severity = except(&[Facet::Severity]);
    let signal = except(&[Facet::Signal]);
    let package = except(&[Facet::Package]);
    let group = except(&[Facet::State, Facet::Assignee]);
    let assignee = except(&[Facet::Assignee]);
    let lc_side = "r.grp = ($8::text IS NOT NULL)";
    format!(
        "counts AS (
  SELECT jsonb_build_object(
    'state', (SELECT jsonb_build_object('open', count(*) FILTER (WHERE r.st_open),
                'mitigated', count(*) FILTER (WHERE r.st_mitigated),
                'accepted_risk', count(*) FILTER (WHERE r.st_accepted_risk),
                'false_positive', count(*) FILTER (WHERE r.st_false_positive),
                'resolved', count(*) FILTER (WHERE r.st_resolved), 'all', count(*) FILTER (WHERE r.m_a))
              FROM r WHERE {MAIN} AND {state}),
    'severity', (SELECT COALESCE(jsonb_object_agg(({SEVERITIES})[r.sev], r.n), '{{}}')
                 FROM (SELECT r.sev, count(*) AS n FROM r WHERE {MAIN} AND {severity} GROUP BY r.sev) r),
    'signal', (SELECT jsonb_build_object(
                 'exploited', count(*) FILTER (WHERE NOT r.lc AND r.exploited),
                 'due30', count(*) FILTER (WHERE NOT r.lc AND r.kev_due <= $13::date + 30),
                 'nofix', count(*) FILTER (WHERE NOT r.lc AND NOT r.fix),
                 'reboot', count(*) FILTER (WHERE NOT r.lc AND r.reboot),
                 'lowconf', count(*) FILTER (WHERE r.lc))
               FROM r WHERE {lc_side} AND {signal}),
    'packages', (SELECT COALESCE(jsonb_agg(jsonb_build_array(p.name, p.n) ORDER BY p.n DESC, p.name), '[]')
                 FROM (SELECT * FROM (SELECT nm AS name, count(*) AS n FROM r CROSS JOIN unnest(r.names) nm
                                      WHERE {MAIN} AND {package} GROUP BY nm ORDER BY 2 DESC, 1 LIMIT 50) top
                       UNION
                       SELECT $7, (SELECT count(*) FROM r WHERE {MAIN} AND {package} AND $7 = ANY(r.names))
                       WHERE EXISTS (SELECT 1 FROM r WHERE {MAIN} AND $7 = ANY(r.names))) p),
    'groups', (SELECT COALESCE(jsonb_agg(jsonb_build_array(g.asset_group_id::text, g.name, g.kind, COALESCE(c.n, 0))), '[]')
               FROM console_asset_groups g LEFT JOIN (
                 SELECT gl.gid, count(*) AS n
                 FROM glist, unnest(glist.ids) WITH ORDINALITY gl(gid, ord) JOIN r ON get_bit(r.mask, gl.ord::int - 1) = 1
                 WHERE r.lc = ($6::text IS NOT DISTINCT FROM 'lowconf') AND NOT r.grp AND {group}
                 GROUP BY gl.gid) c ON c.gid = g.asset_group_id::text
               WHERE c.n > 0
                  OR (g.asset_group_id::text = lower($8) AND ($1::boolean OR g.asset_group_id::text = ANY($2::text[])))),
    'unassigned', (SELECT count(*) FROM r WHERE {MAIN} AND {assignee} AND r.un),
    'people', (SELECT COALESCE(jsonb_agg(jsonb_build_array(u.user_id::text, u.display_name, c.n)), '[]')
               FROM (SELECT kp.assignee, count(*) AS n FROM r JOIN kpers kp
                       ON kp.key = r.key AND kp.lc = r.lc AND kp.grp = r.grp AND kp.s_ok
                     WHERE {MAIN} AND {assignee} GROUP BY kp.assignee) c
               JOIN console_users u ON u.user_id = c.assignee)) AS counts)"
    )
}

/// CTE `summary`: over the rows matching every filter but the state's,
/// those with an open pair (matching the Assignee filter): how many, on how
/// many hosts, and how many are exploited, have a due date, have no fix,
/// or have no open pair assigned. Hosts: those of profiles with an open
/// version pair of those rows' advisories (`sum_adv`), then the other hosts
/// probed for an open fixable one through the primary key.
fn summary() -> String {
    let rows = format!("{MAIN} AND {} AND r.st_open", except(&[Facet::State]));
    let lc = "($6::text IS NOT DISTINCT FROM 'lowconf')";
    let assignee = ASSIGNEE_OK.replace("c.assignee", "t.assigned_to");
    format!(
        "sum_adv AS MATERIALIZED (SELECT DISTINCT unnest(r.advisories) AS advisory_id FROM r WHERE {rows}),
counted AS MATERIALIZED (
  SELECT unnest(p.agents) AS agent_id FROM prof p
  WHERE p.n_in > 0 AND $11::text IS NULL
    AND EXISTS (SELECT 1 FROM pv_adv pa WHERE pa.prof = p.id AND pa.lc = {lc}
                  AND pa.advisory_id IN (SELECT advisory_id FROM sum_adv))
  UNION
  SELECT x.agent_id FROM vx x
  WHERE x.in_group AND $11::text IS NULL AND NOT {lc} AND x.advisory_id IN (SELECT advisory_id FROM sum_adv)),
summary AS (
  SELECT jsonb_build_object(
    'open_rows', count(*),
    'exploited', count(*) FILTER (WHERE r.exploited),
    'with_due', count(*) FILTER (WHERE r.kev_due IS NOT NULL),
    'no_fix', count(*) FILTER (WHERE NOT r.fix),
    'unassigned', count(*) FILTER (WHERE r.people = 0),
    'hosts', (SELECT count(*) FROM counted) + (
        SELECT count(*) FROM hosts h
        WHERE h.in_group AND h.agent_id NOT IN (SELECT agent_id FROM counted)
          AND EXISTS (SELECT 1 FROM vulnerabilities v JOIN advisories a ON a.advisory_id = v.advisory_id
                      LEFT JOIN vulnerability_triage t ON t.agent_id = v.agent_id AND t.advisory_id = v.advisory_id
                      WHERE v.agent_id = h.agent_id
                        AND v.advisory_id = ANY((SELECT array_agg(advisory_id) FROM sum_adv)::text[])
                        AND COALESCE({PAIR_STATE}, 'open') = 'open'
                        AND {assignee} AND ({LOW_CONFIDENCE}) = {lc}))) AS summary
  FROM r WHERE {rows})"
    )
}

/// The sort keys over a `p` row, nulls last, ending in the key tie-break.
fn order(sort: VulnSort, descending: bool) -> String {
    let dir = if descending { "DESC" } else { "ASC" };
    let keys: &[&str] = match sort {
        VulnSort::Priority => &["p.exploited::int", "p.pct", "6 - p.sev", "p.cvss"],
        VulnSort::Severity => &["6 - p.sev"],
        VulnSort::Cvss => &["p.cvss"],
        VulnSort::Epss => &["p.epss"],
        VulnSort::Open => &["p.open"],
        VulnSort::Due => &["p.kev_due"],
    };
    keys.iter()
        .map(|k| format!("{k} {dir} NULLS LAST"))
        .chain([format!("p.key {dir}")])
        .collect::<Vec<_>>()
        .join(", ")
}

/// The statement: the meta (total, counts, summary) as JSON on the first
/// row only, then the page (`$14` limit, `$15` offset) with each row's
/// assignee summary and the other CVEs its advisories name. An empty page
/// still returns one row, with the meta and no key.
pub(crate) fn statement(sort: VulnSort, descending: bool) -> String {
    let all = except(&[]);
    let order = order(sort, descending);
    format!(
        "WITH {hosts}, {fixable}, {profiles}, {cube}, {rows}, {counts}, {summary},
meta AS (
  SELECT jsonb_build_object('total', (SELECT count(*) FROM r WHERE {MAIN} AND {all}),
                            'counts', (SELECT counts FROM counts),
                            'summary', COALESCE((SELECT summary FROM summary), '{{}}')) AS meta),
page AS (
  SELECT p.*, row_number() OVER (ORDER BY {order}) AS ord
  FROM (SELECT * FROM r WHERE {MAIN} AND {all}) p ORDER BY {order} LIMIT $14 OFFSET $15)
SELECT CASE WHEN p.ord IS NOT DISTINCT FROM (SELECT min(ord) FROM page) THEN m.meta END,
       p.key, p.title, ({SEVERITIES})[p.sev], p.exploited, p.kev_due, p.cvss, p.epss, p.pct,
       p.names, p.fixed, p.open, p.total, p.reboot, p.lc, p.advisories,
       ARRAY(SELECT DISTINCT ac.cve_id FROM advisory_cves ac
             WHERE ac.advisory_id = ANY(p.advisories) AND ac.cve_id <> p.key ORDER BY 1 LIMIT 10),
       p.people, p.person, u.display_name
FROM meta m LEFT JOIN page p ON true
LEFT JOIN console_users u ON u.user_id::text = p.person
ORDER BY p.ord",
        hosts = hosts(),
        fixable = fixable(),
        profiles = profiles(),
        cube = cube(),
        rows = rows(),
        counts = counts(),
        summary = summary(),
    )
}
