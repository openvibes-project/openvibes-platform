//! The SQL of the Software list's one statement (step 5g rulings 1–10). The
//! hosts in reach are numbered (`reach`); `pc` counts the hosts of each
//! package version, `pn` folds those into one row per name (versions,
//! managers), and `hn` counts the hosts exactly for the names with several
//! versions, where one host may hold two (`nm`); the open advisories of a
//! name come from the fixable pairs in `vulnerabilities` and the no-fix pairs of the versions in use
//! (`version_vulnerabilities`); `p` joins them with the change log's week
//! and every filter, count and the page read `p`. Only fixed internal
//! strings are formatted in; every value is bound.
//!
//! Parameters: `$1` global scope, `$2` scope group ids, `$3` search, `$4`
//! vulnerabilities, `$5` fix, `$6` versions, `$7` type, `$8` group, `$9`
//! changes, `$10` host, `$11` now, `$12` limit, `$13` offset, `$14` and
//! `$15` the service map's (base, package) pairs, `$16` the packages every
//! `systemd-*` unit may come from.

use crate::{
    console_read::agent_visibility,
    service_names::base_sql,
    software_list::SoftwareSort,
    vuln_list_sql::{LOW_CONFIDENCE, SEVERITIES},
};

/// The filters, each a condition over a `p` row.
#[derive(Clone, Copy, PartialEq)]
enum Facet {
    Search,
    Vulns,
    Fix,
    Versions,
    Kind,
    Group,
    Changes,
    Host,
}

const ALL: [Facet; 8] = [
    Facet::Search,
    Facet::Vulns,
    Facet::Fix,
    Facet::Versions,
    Facet::Kind,
    Facet::Group,
    Facet::Changes,
    Facet::Host,
];

fn filter(facet: Facet) -> &'static str {
    match facet {
        Facet::Search => {
            "($3::text IS NULL OR position(lower($3) in lower(p.name)) > 0
              OR p.name IN (SELECT name FROM ubn WHERE position(lower($3) in lower(unit)) > 0))"
        }
        Facet::Vulns => {
            "($4::text IS NULL OR ($4 = 'exploited' AND p.exploited)
              OR ($4 = 'critical_high' AND p.sev <= 2) OR ($4 = 'any' AND p.adv > 0)
              OR ($4 = 'none' AND p.adv = 0))"
        }
        Facet::Fix => {
            "($5::text IS NULL OR ($5 = 'available' AND p.upd_hosts > 0)
              OR ($5 = 'none' AND p.no_fix > 0))"
        }
        Facet::Versions => {
            "($6::text IS NULL OR ($6 = 'one' AND p.versions = 1)
              OR ($6 = 'several' AND p.versions > 1))"
        }
        Facet::Kind => "($7::text IS NULL OR ($7 = 'dpkg' AND p.dpkg) OR ($7 = 'rpm' AND p.rpm))",
        Facet::Group => "($8::text IS NULL OR p.name IN (SELECT name FROM gsel))",
        Facet::Changes => {
            "($9::text IS NULL OR ($9 = 'new' AND p.added > 0)
              OR ($9 = 'updated' AND p.updated > 0) OR ($9 = 'removed' AND p.removed > 0))"
        }
        Facet::Host => "($10::text IS NULL OR p.name IN (SELECT name FROM hsel))",
    }
}

/// Every filter but `skip`: the rows a facet's value counts are taken from.
fn except(skip: Option<Facet>) -> String {
    let parts: Vec<_> = ALL
        .iter()
        .filter(|f| Some(**f) != skip)
        .map(|f| filter(*f))
        .collect();
    parts.join(" AND ")
}

/// The statement for `sort` in the given direction.
pub(crate) fn statement(sort: SoftwareSort, descending: bool) -> String {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let dir = if descending { "DESC" } else { "ASC" };
    let order = match sort {
        SoftwareSort::Package => format!("m.name {dir}"),
        SoftwareSort::Hosts => format!("m.hosts {dir}, m.name {dir}"),
        SoftwareSort::Vulnerabilities => {
            format!("m.exploited {dir}, (6 - COALESCE(m.sev, 6)) {dir}, m.adv {dir}, m.name {dir}")
        }
        SoftwareSort::Versions => format!("m.versions {dir}, m.name {dir}"),
        SoftwareSort::Week => {
            format!("(m.added + m.updated + m.removed) {dir}, m.name {dir}")
        }
    };
    let (all, no_vulns, no_fix, no_versions, no_kind, no_changes) = (
        except(None),
        except(Some(Facet::Vulns)),
        except(Some(Facet::Fix)),
        except(Some(Facet::Versions)),
        except(Some(Facet::Kind)),
        except(Some(Facet::Changes)),
    );
    let unit_base = base_sql("s.unit");
    // Hosts of a name with several versions count a host once, which takes
    // a pass over their links. Only a sort by hosts needs it for every
    // name; otherwise it is counted for the names on the page.
    let hn = |names: &str| {
        format!(
            "hn AS MATERIALIZED (
           SELECT pv.name, count(DISTINCT hp.agent_id) AS hosts
           FROM host_packages hp JOIN package_versions pv ON pv.id = hp.package_version_id
           WHERE pv.name IN (SELECT name FROM pn WHERE n > 1{names})
             AND hp.agent_id IN (SELECT agent_id FROM reach)
           GROUP BY pv.name)"
        )
    };
    let exact = sort == SoftwareSort::Hosts;
    let (hn_all, hosts, join_hn, hn_page, page_hosts, join_page_hn) = if exact {
        (
            format!("{},", hn("")),
            "COALESCE(hn.hosts, pn.hosts)",
            "LEFT JOIN hn ON hn.name = pn.name",
            String::new(),
            "page.hosts",
            "",
        )
    } else {
        (
            String::new(),
            "pn.hosts",
            "",
            format!("{},", hn(" AND name IN (SELECT name FROM page)")),
            "COALESCE(hn.hosts, page.hosts) AS hosts",
            "LEFT JOIN hn ON hn.name = page.name",
        )
    };
    format!(
        "WITH reach AS MATERIALIZED (
           SELECT a.agent_id, a.status, a.inventory_at, row_number() OVER () AS aid FROM agents a
           WHERE a.status <> 'revoked' AND {visible}),
         wide AS MATERIALIZED (
           SELECT (SELECT count(*) FROM reach) * 2 >= (SELECT count(*) FROM agents) AS wide),
         pc AS MATERIALIZED (
           SELECT d.pvid, sum(d.n)::bigint AS hosts
           FROM (SELECT hp.package_version_id AS pvid, count(*) AS n
                 FROM host_packages hp WHERE (SELECT wide FROM wide) GROUP BY 1
                 UNION ALL
                 SELECT hp.package_version_id, -count(*)
                 FROM host_packages hp
                 WHERE (SELECT wide FROM wide)
                   AND hp.agent_id IN (SELECT a.agent_id FROM agents a
                                       LEFT JOIN reach r ON r.agent_id = a.agent_id
                                       WHERE r.agent_id IS NULL)
                 GROUP BY 1
                 UNION ALL
                 SELECT hp.package_version_id, count(*)
                 FROM host_packages hp
                 WHERE NOT (SELECT wide FROM wide) AND hp.agent_id IN (SELECT agent_id FROM reach)
                 GROUP BY 1) d
           GROUP BY d.pvid HAVING sum(d.n) > 0),
         vu AS MATERIALIZED (SELECT pvid FROM pc),
         pn AS MATERIALIZED (
           SELECT pv.name, count(*) AS n, sum(pc.hosts)::bigint AS hosts,
                  count(DISTINCT (pv.epoch, pv.version, pv.release)) AS versions,
                  bool_or(pv.manager = 'dpkg') AS dpkg, bool_or(pv.manager = 'rpm') AS rpm
           FROM pc JOIN package_versions pv ON pv.id = pc.pvid GROUP BY pv.name),
         {hn_all}
         nm AS MATERIALIZED (
           SELECT pn.name, {hosts} AS hosts, pn.versions, pn.dpkg, pn.rpm
           FROM pn {join_hn}),
         fx AS MATERIALIZED (
           SELECT e ->> 'name' AS name, v.advisory_id, r.aid, v.reboot_needed
           FROM vulnerabilities v JOIN reach r ON r.agent_id = v.agent_id
           JOIN advisories a ON a.advisory_id = v.advisory_id
           LEFT JOIN vulnerability_triage t ON t.agent_id = v.agent_id AND t.advisory_id = v.advisory_id
           CROSS JOIN LATERAL jsonb_array_elements(v.packages) e
           WHERE v.fixed_at IS NULL AND NOT {LOW_CONFIDENCE}
             AND (t.state IS NULL OR t.state = 'open'
                  OR (t.state = 'accepted_risk' AND t.accepted_until <= $11::timestamptz))),
         nf AS MATERIALIZED (
           SELECT pv.name, vv.advisory_id
           FROM vu JOIN package_versions pv ON pv.id = vu.pvid
           JOIN version_vulnerabilities vv ON vv.package_version_id = vu.pvid),
         adv AS MATERIALIZED (
           SELECT d.name, d.advisory_id, bool_or(d.fix) AS fix
           FROM (SELECT name, advisory_id, true AS fix FROM fx
                 UNION ALL SELECT name, advisory_id, false FROM nf) d
           GROUP BY d.name, d.advisory_id),
         af AS MATERIALIZED (
           SELECT ad.advisory_id, array_position({SEVERITIES}, ad.severity) AS sev,
                  COALESCE(bool_or(x.kev_added IS NOT NULL OR COALESCE(x.euvd_exploited, false)), false) AS exploited
           FROM advisories ad
           LEFT JOIN advisory_cves c ON c.advisory_id = ad.advisory_id
           LEFT JOIN cve_enrichment x ON x.cve_id = c.cve_id
           WHERE ad.advisory_id IN (SELECT advisory_id FROM adv)
           GROUP BY ad.advisory_id, ad.severity),
         rk AS (
           SELECT a.name, count(*) AS adv, count(*) FILTER (WHERE NOT a.fix) AS no_fix,
                  min(af.sev) AS sev, bool_or(af.exploited) AS exploited
           FROM adv a JOIN af ON af.advisory_id = a.advisory_id GROUP BY a.name),
         uh AS (
           SELECT name, count(DISTINCT aid) AS hosts FROM fx WHERE NOT reboot_needed GROUP BY name),
         uu AS MATERIALIZED (
           SELECT s.unit, {unit_base} AS base, count(DISTINCT r.aid) AS hosts
           FROM host_services s JOIN reach r ON r.agent_id = s.agent_id GROUP BY s.unit),
         cand AS (
           SELECT DISTINCT uu.base AS b, uu.base AS pkg FROM uu
           UNION
           SELECT m.b, m.pkg FROM unnest($14::text[], $15::text[]) AS m(b, pkg)
           UNION
           SELECT uu.base, s.pkg FROM uu CROSS JOIN unnest($16::text[]) AS s(pkg) WHERE uu.base LIKE 'systemd-%'),
         ubn AS MATERIALIZED (
           SELECT nm.name, uu.unit, uu.hosts
           FROM nm JOIN cand c ON c.pkg = lower(nm.name) JOIN uu ON uu.base = c.b),
         wk AS (
           SELECT d.name, count(*) FILTER (WHERE d.app AND NOT d.gone) AS added,
                  count(*) FILTER (WHERE d.app AND d.gone) AS updated,
                  count(*) FILTER (WHERE d.gone AND NOT d.app) AS removed
           FROM (SELECT c.key AS name, c.agent_id, bool_or(c.change = 'appeared') AS app,
                        bool_or(c.change = 'went_away') AS gone
                 FROM change_log c JOIN reach r ON r.agent_id = c.agent_id
                 WHERE c.kind = 'package' AND c.change IN ('appeared', 'went_away')
                   AND c.at > $11::timestamptz - interval '7 days'
                 GROUP BY c.key, c.agent_id) d
           GROUP BY d.name),
         gsel AS (
           SELECT DISTINCT pv.name
           FROM (SELECT DISTINCT hp.package_version_id AS pvid FROM host_packages hp
                 WHERE $8::text IS NOT NULL
                   AND hp.agent_id IN (SELECT m.agent_id FROM console_host_group_membership m
                                       JOIN reach r ON r.agent_id = m.agent_id
                                       WHERE m.asset_group_id::text = lower($8::text))) g
           JOIN package_versions pv ON pv.id = g.pvid),
         hsel AS (
           SELECT DISTINCT pv.name
           FROM host_packages hp JOIN package_versions pv ON pv.id = hp.package_version_id
           WHERE $10::text IS NOT NULL AND hp.agent_id = $10::text
             AND hp.agent_id IN (SELECT agent_id FROM reach)),
         p AS (
           SELECT nm.*, COALESCE(rk.adv, 0) AS adv, COALESCE(rk.no_fix, 0) AS no_fix, rk.sev,
                  COALESCE(rk.exploited, false) AS exploited, COALESCE(uh.hosts, 0) AS upd_hosts,
                  COALESCE(wk.added, 0) AS added, COALESCE(wk.updated, 0) AS updated,
                  COALESCE(wk.removed, 0) AS removed
           FROM nm LEFT JOIN rk ON rk.name = nm.name LEFT JOIN uh ON uh.name = nm.name
           LEFT JOIN wk ON wk.name = nm.name),
         m AS (SELECT p.* FROM p WHERE {all}),
         page AS (SELECT m.* FROM m ORDER BY {order} LIMIT $12 OFFSET $13),
         {hn_page}
         meta AS (
           SELECT jsonb_build_object(
             'total', (SELECT count(*) FROM m),
             'counts', jsonb_build_object(
               'vulns', jsonb_build_object(
                 'exploited', (SELECT count(*) FROM p WHERE {no_vulns} AND p.exploited),
                 'critical_high', (SELECT count(*) FROM p WHERE {no_vulns} AND p.sev <= 2),
                 'any', (SELECT count(*) FROM p WHERE {no_vulns} AND p.adv > 0),
                 'none', (SELECT count(*) FROM p WHERE {no_vulns} AND p.adv = 0)),
               'fix', jsonb_build_object(
                 'available', (SELECT count(*) FROM p WHERE {no_fix} AND p.upd_hosts > 0),
                 'none', (SELECT count(*) FROM p WHERE {no_fix} AND p.no_fix > 0)),
               'versions', jsonb_build_object(
                 'one', (SELECT count(*) FROM p WHERE {no_versions} AND p.versions = 1),
                 'several', (SELECT count(*) FROM p WHERE {no_versions} AND p.versions > 1)),
               'kind', jsonb_build_object(
                 'dpkg', (SELECT count(*) FROM p WHERE {no_kind} AND p.dpkg),
                 'rpm', (SELECT count(*) FROM p WHERE {no_kind} AND p.rpm)),
               'changes', jsonb_build_object(
                 'new', (SELECT count(*) FROM p WHERE {no_changes} AND p.added > 0),
                 'updated', (SELECT count(*) FROM p WHERE {no_changes} AND p.updated > 0),
                 'removed', (SELECT count(*) FROM p WHERE {no_changes} AND p.removed > 0)),
               'groups', (SELECT COALESCE(jsonb_agg(jsonb_build_array(g.asset_group_id::text, g.name, g.kind, c.n)), '[]')
                          FROM console_asset_groups g JOIN (
                            SELECT m2.asset_group_id AS gid, count(*) AS n
                            FROM console_host_group_membership m2 JOIN reach r ON r.agent_id = m2.agent_id
                            GROUP BY m2.asset_group_id) c ON c.gid = g.asset_group_id)),
             'summary', jsonb_build_object(
               'exploited', (SELECT count(*) FROM m WHERE m.exploited),
               'fixable', (SELECT count(*) FROM m WHERE m.upd_hosts > 0),
               'several_versions', (SELECT count(*) FROM m WHERE m.versions > 1),
               'new_this_week', (SELECT count(*) FROM m WHERE m.added > 0),
               'reporting_hosts', (SELECT count(*) FROM reach a
                                   WHERE a.status = 'active' AND a.inventory_at IS NOT NULL))
           ) AS meta)
         SELECT meta.meta, page.name, {page_hosts}, page.versions, page.dpkg, page.rpm, page.adv, page.sev,
                page.exploited, page.no_fix, page.upd_hosts, page.added, page.updated, page.removed,
                (SELECT COALESCE(jsonb_agg(jsonb_build_array(u.unit, u.hosts) ORDER BY u.hosts DESC, u.unit), '[]')
                 FROM ubn u WHERE u.name = page.name) AS used_by,
                (SELECT COALESCE(jsonb_agg(DISTINCT jsonb_build_array(pv.epoch, pv.version, pv.release)), '[]')
                 FROM vu JOIN package_versions pv ON pv.id = vu.pvid WHERE pv.name = page.name) AS versions_in_use
         FROM meta LEFT JOIN page ON true {join_page_hn}
         ORDER BY {order_page}",
        order_page = order.replace("m.", "page.")
    )
}
