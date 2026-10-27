//! The SQL of the Services list's one statement (step 5f rulings 1–10). Each
//! host counts once per unit (`hx`); `p` folds `hx` into one row per unit
//! with its change-log week and its Needs a look codes; every filter, count
//! and the page read `p`. Only fixed internal strings are formatted in;
//! every value is bound.
//!
//! `pmg` reaches `host_packages` through a lateral index lookup per matched
//! package version: left to itself the planner scans every installed package
//! of every host (20 million rows on the timing fleet).
//!
//! Parameters: `$1` global scope, `$2` scope group ids, `$3` search, `$4`
//! bases whose usual name matches the search, `$5` runs as, `$6` listens,
//! `$7` packaged, `$8` group, `$9` changes, `$10` host, `$11` now, `$12`
//! limit, `$13` offset, `$14` bases of databases, `$15` bases of remote
//! admin, `$16` bases of every known service, `$17` and `$18` the map's
//! (base, package) pairs.

use crate::{
    console_read::agent_visibility,
    service_list::ServiceSort,
    service_names::{self, base_sql},
};

/// The filters, each a condition over a `p` row.
#[derive(Clone, Copy, PartialEq)]
enum Facet {
    Search,
    RunsAs,
    Listens,
    Packaged,
    Group,
    Changes,
    Host,
}

const ALL: [Facet; 7] = [
    Facet::Search,
    Facet::RunsAs,
    Facet::Listens,
    Facet::Packaged,
    Facet::Group,
    Facet::Changes,
    Facet::Host,
];

fn filter(facet: Facet) -> &'static str {
    match facet {
        Facet::Search => {
            "($3::text IS NULL OR p.base = ANY($4::text[])
              OR position(lower($3) in lower(p.unit)) > 0
              OR position(lower($3) in lower(coalesce(p.pkg, ''))) > 0
              OR p.uid IN (SELECT uid FROM usp)
              OR p.unit IN (SELECT unit FROM ups))"
        }
        Facet::RunsAs => {
            "($5::text IS NULL OR ($5 = 'root' AND p.priv_hosts > 0)
              OR ($5 = 'other' AND p.priv_hosts = 0))"
        }
        Facet::Listens => {
            "($6::text IS NULL OR ($6 = 'exposed' AND p.exposed_hosts > 0)
              OR ($6 = 'local' AND p.listen_hosts > 0 AND p.exposed_hosts = 0)
              OR ($6 = 'none' AND p.listen_hosts = 0))"
        }
        Facet::Packaged => {
            "($7::text IS NULL OR ($7 = 'yes' AND p.pk_hosts = p.hosts)
              OR ($7 = 'no' AND p.pk_hosts < p.hosts))"
        }
        Facet::Group => "($8::text IS NULL OR p.uid IN (SELECT uid FROM gsel))",
        Facet::Changes => {
            "($9::text IS NULL OR ($9 = 'new' AND p.added > 0)
              OR ($9 = 'look' AND cardinality(p.look) > 0))"
        }
        Facet::Host => "($10::text IS NULL OR p.uid IN (SELECT uid FROM hsel))",
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
pub(crate) fn statement(sort: ServiceSort, descending: bool) -> String {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let dir = if descending { "DESC" } else { "ASC" };
    let order = match sort {
        ServiceSort::Service => format!("m.unit {dir}"),
        ServiceSort::Hosts => format!("m.hosts {dir}, m.unit {dir}"),
        ServiceSort::Week => format!("m.added {dir}, m.unit {dir}"),
    };
    let (all, no_runs_as, no_listens, no_packaged, no_group, no_changes) = (
        except(None),
        except(Some(Facet::RunsAs)),
        except(Some(Facet::Listens)),
        except(Some(Facet::Packaged)),
        except(Some(Facet::Group)),
        except(Some(Facet::Changes)),
    );
    let unit_base = base_sql("u.unit");
    let systemd = service_names::SYSTEMD
        .iter()
        .map(|p| format!("'{p}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "WITH reach AS MATERIALIZED (
           SELECT a.agent_id, a.status, a.services_at, row_number() OVER () AS aid FROM agents a
           WHERE a.status <> 'revoked' AND {visible}),
         ub AS MATERIALIZED (
           SELECT u.unit, {unit_base} AS base, row_number() OVER () AS uid
           FROM (SELECT DISTINCT unit FROM host_services) u),
         hu AS MATERIALIZED (
           SELECT a.aid, ub.uid, s.programs, s.run_as,
                  lower(coalesce(s.run_as, '')) IN ('root', '0', 'system', 'localsystem', 'nt authority\\system') AS priv
           FROM host_services s JOIN reach a ON a.agent_id = s.agent_id JOIN ub ON ub.unit = s.unit),
         cand AS (
           SELECT DISTINCT ub.base AS b, ub.base AS p FROM ub
           UNION
           SELECT m.b, m.p FROM unnest($17::text[], $18::text[]) AS m(b, p)
           UNION
           SELECT ub.base, p FROM ub CROSS JOIN unnest(ARRAY[{systemd}]) AS p WHERE ub.base LIKE 'systemd-%'),
         mpv AS MATERIALIZED (
           SELECT c.b, pv.id, pv.name
           FROM cand c JOIN package_versions pv ON lower(pv.name) = c.p),
         pm AS MATERIALIZED (
           SELECT a.aid, x.b, min(x.name) AS pkg
           FROM (SELECT hp.agent_id, m.b, m.name FROM mpv m
                 CROSS JOIN LATERAL (SELECT h.agent_id FROM host_packages h
                                     WHERE h.package_version_id = m.id OFFSET 0) hp) x
           JOIN reach a ON a.agent_id = x.agent_id
           GROUP BY a.aid, x.b),
         pmg AS MATERIALIZED (
           SELECT pm.aid, ub.uid, pm.pkg FROM pm JOIN ub ON ub.base = pm.b),
         lg AS (
           SELECT a.aid, ub.uid, bool_or(l.exposed) AS exposed
           FROM host_listeners l JOIN reach a ON a.agent_id = l.agent_id JOIN ub ON ub.unit = l.service
           GROUP BY a.aid, ub.uid),
         hx AS MATERIALIZED (
           SELECT hu.aid, hu.uid, hu.priv, pmg.pkg,
                  lg.aid IS NOT NULL AS lis, COALESCE(lg.exposed, false) AS exp
           FROM hu LEFT JOIN pmg ON pmg.aid = hu.aid AND pmg.uid = hu.uid
           LEFT JOIN lg ON lg.aid = hu.aid AND lg.uid = hu.uid),
         ups AS (
           SELECT DISTINCT l.service AS unit
           FROM host_listeners l JOIN reach a ON a.agent_id = l.agent_id
           WHERE $3::text IS NOT NULL AND l.service IS NOT NULL
             AND position(lower($3) in l.port::text || '/' || l.protocol) > 0),
         usp AS (
           SELECT DISTINCT x.uid
           FROM hu x, unnest(x.programs) pr
           WHERE $3::text IS NOT NULL AND position(lower($3) in lower(pr)) > 0),
         wk AS (
           SELECT d.key AS unit,
                  count(*) FILTER (WHERE d.change = 'appeared') AS added,
                  count(*) FILTER (WHERE d.change = 'went_away') AS removed
           FROM (SELECT DISTINCT c.key, c.change, c.agent_id
                 FROM change_log c JOIN reach a ON a.agent_id = c.agent_id
                 WHERE c.kind = 'service' AND c.change IN ('appeared', 'went_away')
                   AND c.at > $11::timestamptz - interval '7 days') d
           GROUP BY d.key),
         gp AS MATERIALIZED (
           SELECT m.asset_group_id, h.uid, count(*) AS hosts
           FROM hx h JOIN reach r ON r.aid = h.aid
           JOIN console_host_group_membership m ON m.agent_id = r.agent_id
           GROUP BY m.asset_group_id, h.uid),
         gsel AS (
           SELECT uid FROM gp WHERE asset_group_id::text = lower($8::text)),
         hsel AS (
           SELECT h.uid FROM hx h JOIN reach r ON r.aid = h.aid WHERE r.agent_id = $10::text),
         p0 AS (
           SELECT u.unit, u.base, x.*
           FROM (SELECT h.uid, count(*) AS hosts,
                        count(*) FILTER (WHERE h.priv) AS priv_hosts,
                        count(*) FILTER (WHERE h.pkg IS NOT NULL) AS pk_hosts,
                        count(*) FILTER (WHERE h.priv AND h.pkg IS NULL) AS bad_hosts,
                        count(*) FILTER (WHERE h.exp) AS exposed_hosts,
                        count(*) FILTER (WHERE h.lis) AS listen_hosts,
                        min(h.pkg) AS pkg
                 FROM hx h GROUP BY h.uid) x JOIN ub u ON u.uid = x.uid),
         p AS (
           SELECT p0.*, COALESCE(wk.added, 0) AS added, COALESCE(wk.removed, 0) AS removed,
                  array_remove(ARRAY[
                    CASE WHEN p0.bad_hosts > 0 THEN 'root_unpackaged' END,
                    CASE WHEN p0.base = ANY($14::text[]) AND p0.exposed_hosts > 0 THEN 'database_exposed' END,
                    CASE WHEN p0.base = ANY($15::text[]) AND p0.exposed_hosts > 0 THEN 'remote_admin_exposed' END,
                    CASE WHEN NOT p0.base = ANY($16::text[]) AND COALESCE(wk.added, 0) > 0 THEN 'new_unusual' END
                  ], NULL) AS look
           FROM p0 LEFT JOIN wk USING (unit)),
         m AS (SELECT p.* FROM p WHERE {all}),
         page AS (
           SELECT m.* FROM m ORDER BY {order} LIMIT $12 OFFSET $13),
         prg AS (
           SELECT d.uid, array_agg(d.pr ORDER BY d.pr) AS programs
           FROM (SELECT DISTINCT x.uid, pr FROM hu x, unnest(x.programs) pr
                 WHERE x.uid IN (SELECT uid FROM page)) d GROUP BY d.uid),
         ras AS (
           SELECT d.uid, array_agg(d.run_as ORDER BY d.run_as) AS run_as
           FROM (SELECT DISTINCT x.uid, x.run_as FROM hu x
                 WHERE x.run_as IS NOT NULL AND x.uid IN (SELECT uid FROM page)) d GROUP BY d.uid),
         up AS (
           SELECT l.service AS unit, l.protocol, l.port, bool_or(l.exposed) AS exposed,
                  count(DISTINCT l.agent_id) AS hosts
           FROM host_listeners l JOIN reach a ON a.agent_id = l.agent_id
           WHERE l.service IN (SELECT unit FROM page)
           GROUP BY l.service, l.protocol, l.port),
         meta AS (
           SELECT jsonb_build_object(
             'total', (SELECT count(*) FROM m),
             'counts', jsonb_build_object(
               'runs_as', jsonb_build_object(
                 'root', (SELECT count(*) FROM p WHERE {no_runs_as} AND p.priv_hosts > 0),
                 'other', (SELECT count(*) FROM p WHERE {no_runs_as} AND p.priv_hosts = 0)),
               'listens', jsonb_build_object(
                 'exposed', (SELECT count(*) FROM p WHERE {no_listens} AND p.exposed_hosts > 0),
                 'local', (SELECT count(*) FROM p WHERE {no_listens} AND p.listen_hosts > 0 AND p.exposed_hosts = 0),
                 'none', (SELECT count(*) FROM p WHERE {no_listens} AND p.listen_hosts = 0)),
               'packaged', jsonb_build_object(
                 'yes', (SELECT count(*) FROM p WHERE {no_packaged} AND p.pk_hosts = p.hosts),
                 'no', (SELECT count(*) FROM p WHERE {no_packaged} AND p.pk_hosts < p.hosts)),
               'changes', jsonb_build_object(
                 'new', (SELECT count(*) FROM p WHERE {no_changes} AND p.added > 0),
                 'look', (SELECT count(*) FROM p WHERE {no_changes} AND cardinality(p.look) > 0)),
               'groups', (SELECT COALESCE(jsonb_agg(jsonb_build_array(g.asset_group_id::text, g.name, g.kind, COALESCE(c.n, 0))), '[]')
                          FROM console_asset_groups g LEFT JOIN (
                            SELECT gp.asset_group_id AS gid, count(*) AS n
                            FROM gp JOIN p ON p.uid = gp.uid
                            WHERE {no_group} GROUP BY gp.asset_group_id) c ON c.gid = g.asset_group_id
                          WHERE c.n > 0
                             OR (g.asset_group_id::text = lower($8::text)
                                 AND ($1::boolean OR g.asset_group_id::text = ANY($2::text[]))))),
             'summary', jsonb_build_object(
               'root', (SELECT count(*) FROM m WHERE m.priv_hosts > 0),
               'exposed', (SELECT count(*) FROM m WHERE m.exposed_hosts > 0),
               'not_packaged', (SELECT count(*) FROM m WHERE m.pk_hosts < m.hosts),
               'new_this_week', (SELECT count(*) FROM m WHERE m.added > 0),
               'need_a_look', (SELECT count(*) FROM m WHERE cardinality(m.look) > 0),
               'reporting_hosts', (SELECT count(*) FROM reach a
                                   WHERE a.status = 'active' AND a.services_at IS NOT NULL))
           ) AS meta)
         SELECT meta.meta, page.unit, page.hosts, page.priv_hosts, page.pk_hosts, page.exposed_hosts,
                page.listen_hosts, COALESCE(ras.run_as, '{{}}') AS run_as, COALESCE(prg.programs, '{{}}') AS programs, page.pkg, page.added, page.removed, page.look,
                (SELECT COALESCE(jsonb_agg(jsonb_build_array(g.asset_group_id::text, g.name, g.kind, gp.hosts)
                                           ORDER BY gp.hosts DESC, lower(g.name), g.asset_group_id), '[]')
                 FROM gp JOIN console_asset_groups g ON g.asset_group_id = gp.asset_group_id
                 WHERE gp.uid = page.uid AND g.kind <> 'manual') AS groups,
                (SELECT COALESCE(jsonb_agg(jsonb_build_array(u.protocol, u.port, u.exposed, u.hosts)
                                           ORDER BY u.exposed DESC, u.port, u.protocol), '[]')
                 FROM up u WHERE u.unit = page.unit) AS ports,
                page.base
         FROM meta LEFT JOIN page ON true LEFT JOIN prg ON prg.uid = page.uid LEFT JOIN ras ON ras.uid = page.uid
         ORDER BY {order_page}",
        order_page = order.replace("m.", "page.")
    )
}
