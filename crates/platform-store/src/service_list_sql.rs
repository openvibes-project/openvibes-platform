//! The SQL of the Services list's one statement (step 5f rulings 1–10). Each
//! host counts once per unit (`hx`); `p` folds `hx` into one row per unit
//! with its change-log week and its Needs a look codes; every filter, count
//! and the page read `p`. Only fixed internal strings are formatted in;
//! every value is bound.
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
    service_names::base_sql,
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
              OR EXISTS (SELECT 1 FROM unnest(p.programs) s WHERE position(lower($3) in lower(s)) > 0)
              OR EXISTS (SELECT 1 FROM up WHERE up.unit = p.unit
                         AND position(lower($3) in up.port::text || '/' || up.protocol) > 0))"
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
        Facet::Group => "($8::text IS NULL OR p.unit IN (SELECT unit FROM gsel))",
        Facet::Changes => {
            "($9::text IS NULL OR ($9 = 'new' AND p.added > 0)
              OR ($9 = 'look' AND cardinality(p.look) > 0))"
        }
        Facet::Host => "($10::text IS NULL OR p.unit IN (SELECT unit FROM hsel))",
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
    let unit_base = base_sql("s.unit");
    let cand_base = base_sql("hu.unit");
    format!(
        "WITH reach AS MATERIALIZED (
           SELECT a.agent_id, a.status, a.services_at FROM agents a
           WHERE a.status <> 'revoked' AND {visible}),
         hu AS MATERIALIZED (
           SELECT s.agent_id, s.unit, {unit_base} AS base, s.programs, s.processes, s.run_as,
                  lower(coalesce(s.run_as, '')) IN ('root', '0', 'system', 'localsystem', 'nt authority\\system') AS priv
           FROM host_services s JOIN reach a ON a.agent_id = s.agent_id),
         cand AS (
           SELECT DISTINCT {cand_base} AS b, {cand_base} AS p FROM hu
           UNION
           SELECT m.b, m.p FROM unnest($17::text[], $18::text[]) AS m(b, p)),
         pmg AS MATERIALIZED (
           SELECT hp.agent_id, c.b AS base, min(pv.name) AS pkg
           FROM cand c JOIN package_versions pv ON lower(pv.name) = c.p
           JOIN host_packages hp ON hp.package_version_id = pv.id
           JOIN reach a ON a.agent_id = hp.agent_id
           GROUP BY hp.agent_id, c.b),
         lo AS MATERIALIZED (
           SELECT l.agent_id, l.service AS unit, l.protocol, l.port, bool_or(l.exposed) AS exposed
           FROM host_listeners l JOIN reach a ON a.agent_id = l.agent_id
           WHERE l.service IS NOT NULL
           GROUP BY l.agent_id, l.service, l.protocol, l.port),
         lg AS (
           SELECT agent_id, unit, bool_or(exposed) AS exposed FROM lo GROUP BY agent_id, unit),
         hx AS MATERIALIZED (
           SELECT hu.agent_id, hu.unit, hu.base, hu.programs, hu.run_as, hu.priv, pmg.pkg,
                  lg.agent_id IS NOT NULL AS lis, COALESCE(lg.exposed, false) AS exp
           FROM hu LEFT JOIN pmg ON pmg.agent_id = hu.agent_id AND pmg.base = hu.base
           LEFT JOIN lg ON lg.agent_id = hu.agent_id AND lg.unit = hu.unit),
         up AS (
           SELECT unit, protocol, port, bool_or(exposed) AS exposed, count(*) AS hosts
           FROM lo GROUP BY unit, protocol, port),
         prg AS (
           SELECT x.unit, array_agg(DISTINCT pr ORDER BY pr) AS programs
           FROM hx x, unnest(x.programs) pr GROUP BY x.unit),
         ras AS (
           SELECT unit, array_agg(DISTINCT run_as ORDER BY run_as) AS run_as
           FROM hx WHERE run_as IS NOT NULL GROUP BY unit),
         wk AS (
           SELECT c.key AS unit,
                  count(DISTINCT c.agent_id) FILTER (WHERE c.change = 'appeared') AS added,
                  count(DISTINCT c.agent_id) FILTER (WHERE c.change = 'went_away') AS removed
           FROM change_log c JOIN reach a ON a.agent_id = c.agent_id
           WHERE c.kind = 'service' AND c.change IN ('appeared', 'went_away')
             AND c.at > $11::timestamptz - interval '7 days'
           GROUP BY c.key),
         gp AS MATERIALIZED (
           SELECT m.asset_group_id, h.unit, count(*) AS hosts
           FROM hx h JOIN console_host_group_membership m ON m.agent_id = h.agent_id
           GROUP BY m.asset_group_id, h.unit),
         gsel AS (
           SELECT unit FROM gp WHERE asset_group_id::text = lower($8::text)),
         hsel AS (
           SELECT unit FROM hx WHERE agent_id = $10::text),
         p0 AS (
           SELECT h.unit, max(h.base) AS base, count(*) AS hosts,
                  count(*) FILTER (WHERE h.priv) AS priv_hosts,
                  count(*) FILTER (WHERE h.pkg IS NOT NULL) AS pk_hosts,
                  count(*) FILTER (WHERE h.priv AND h.pkg IS NULL) AS bad_hosts,
                  count(*) FILTER (WHERE h.exp) AS exposed_hosts,
                  count(*) FILTER (WHERE h.lis) AS listen_hosts,
                  min(h.pkg) AS pkg
           FROM hx h GROUP BY h.unit),
         p AS (
           SELECT p0.*, COALESCE(prg.programs, '{{}}') AS programs, COALESCE(ras.run_as, '{{}}') AS run_as,
                  COALESCE(wk.added, 0) AS added, COALESCE(wk.removed, 0) AS removed,
                  array_remove(ARRAY[
                    CASE WHEN p0.bad_hosts > 0 THEN 'root_unpackaged' END,
                    CASE WHEN p0.base = ANY($14::text[]) AND p0.exposed_hosts > 0 THEN 'database_exposed' END,
                    CASE WHEN p0.base = ANY($15::text[]) AND p0.exposed_hosts > 0 THEN 'remote_admin_exposed' END,
                    CASE WHEN NOT p0.base = ANY($16::text[]) AND COALESCE(wk.added, 0) > 0 THEN 'new_unusual' END
                  ], NULL) AS look
           FROM p0 LEFT JOIN prg USING (unit) LEFT JOIN ras USING (unit) LEFT JOIN wk USING (unit)),
         m AS (SELECT p.* FROM p WHERE {all}),
         page AS (
           SELECT m.* FROM m ORDER BY {order} LIMIT $12 OFFSET $13),
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
                            FROM gp JOIN p ON p.unit = gp.unit
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
                page.listen_hosts, page.run_as, page.programs, page.pkg, page.added, page.removed, page.look,
                (SELECT COALESCE(jsonb_agg(jsonb_build_array(g.asset_group_id::text, g.name, g.kind, gp.hosts)
                                           ORDER BY gp.hosts DESC, lower(g.name), g.asset_group_id), '[]')
                 FROM gp JOIN console_asset_groups g ON g.asset_group_id = gp.asset_group_id
                 WHERE gp.unit = page.unit AND g.kind <> 'manual') AS groups,
                (SELECT COALESCE(jsonb_agg(jsonb_build_array(u.protocol, u.port, u.exposed, u.hosts)
                                           ORDER BY u.exposed DESC, u.port, u.protocol), '[]')
                 FROM up u WHERE u.unit = page.unit) AS ports,
                page.base
         FROM meta LEFT JOIN page ON true
         ORDER BY {order_page}",
        order_page = order.replace("m.", "page.")
    )
}
