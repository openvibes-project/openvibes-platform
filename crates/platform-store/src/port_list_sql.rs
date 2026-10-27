//! The SQL of the Ports list's one statement (step 5e rulings 11–16). Each
//! host counts once per port (`hp`); `p` folds `hp` into one row per port
//! with its change-log week and its Needs a look codes; every filter, count
//! and the page read `p`. Only fixed internal strings are formatted in;
//! every value is bound.
//!
//! Parameters: `$1` global scope, `$2` scope group ids, `$3` search, `$4`
//! keys whose usual name matches the search, `$5` exposure, `$6` protocol,
//! `$7` group, `$8` service (`~none` for an owner not collected), `$9`
//! changes, `$10` host, `$11` now, `$12` limit, `$13` offset, `$14` keys of
//! database ports, `$15` keys of remote-admin ports, `$16` keys of every
//! known port.

use crate::{console_read::agent_visibility, port_list::PortSort};

/// The filters, each a condition over a `p` row.
#[derive(Clone, Copy, PartialEq)]
enum Facet {
    Search,
    Exposure,
    Protocol,
    Group,
    Service,
    Changes,
    Host,
}

const ALL: [Facet; 7] = [
    Facet::Search,
    Facet::Exposure,
    Facet::Protocol,
    Facet::Group,
    Facet::Service,
    Facet::Changes,
    Facet::Host,
];

fn filter(facet: Facet) -> &'static str {
    match facet {
        Facet::Search => {
            "($3::text IS NULL OR p.key = ANY($4::text[])
              OR position(lower($3) in lower(p.key)) > 0
              OR position(lower($3) in lower(p.port::text || '/' || p.protocol)) > 0
              OR EXISTS (SELECT 1 FROM unnest(p.svc) s WHERE position(lower($3) in lower(s)) > 0))"
        }
        Facet::Exposure => {
            "($5::text IS NULL OR ($5 = 'exposed' AND p.exposed_hosts > 0)
              OR ($5 = 'local' AND p.exposed_hosts = 0))"
        }
        Facet::Protocol => "($6::text IS NULL OR p.protocol = $6)",
        Facet::Group => "($7::text IS NULL OR p.key IN (SELECT key FROM gsel))",
        Facet::Service => "($8::text IS NULL OR ($8 = '~none' AND p.unowned) OR $8 = ANY(p.svc))",
        Facet::Changes => {
            "($9::text IS NULL OR ($9 = 'new' AND p.added > 0)
              OR ($9 = 'look' AND cardinality(p.look) > 0))"
        }
        Facet::Host => "($10::text IS NULL OR p.key IN (SELECT key FROM hsel))",
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
pub(crate) fn statement(sort: PortSort, descending: bool) -> String {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let dir = if descending { "DESC" } else { "ASC" };
    let order = match sort {
        PortSort::Port => format!("m.port {dir}, m.protocol {dir}"),
        PortSort::Hosts => format!("m.hosts {dir}, m.port {dir}, m.protocol {dir}"),
        PortSort::Exposed => format!("m.exposed_hosts {dir}, m.port {dir}, m.protocol {dir}"),
        PortSort::Week => format!("m.added {dir}, m.port {dir}, m.protocol {dir}"),
    };
    let (all, no_exposure, no_protocol, no_group, no_service, no_changes) = (
        except(None),
        except(Some(Facet::Exposure)),
        except(Some(Facet::Protocol)),
        except(Some(Facet::Group)),
        except(Some(Facet::Service)),
        except(Some(Facet::Changes)),
    );
    format!(
        "WITH reach AS MATERIALIZED (
           SELECT a.agent_id, a.status, a.services_at FROM agents a
           WHERE a.status <> 'revoked' AND {visible}),
         hp AS MATERIALIZED (
           SELECT l.agent_id, l.protocol, l.port, bool_or(l.exposed) AS exposed,
                  bool_or(l.service IS NULL) AS unowned
           FROM host_listeners l JOIN reach a ON a.agent_id = l.agent_id
           GROUP BY l.agent_id, l.protocol, l.port),
         wk AS (
           SELECT split_part(c.key, '/', 1) AS protocol, split_part(c.key, '/', 2)::int AS port,
                  count(DISTINCT c.agent_id) FILTER (WHERE c.change = 'appeared') AS added,
                  count(DISTINCT c.agent_id) FILTER (WHERE c.change = 'went_away') AS removed
           FROM change_log c JOIN reach a ON a.agent_id = c.agent_id
           WHERE c.kind = 'listener' AND c.change IN ('appeared', 'went_away')
             AND c.at > $11::timestamptz - interval '7 days'
           GROUP BY 1, 2),
         pu AS (
           SELECT DISTINCT l.protocol, l.port, l.service AS unit
           FROM host_listeners l JOIN reach a ON a.agent_id = l.agent_id
           WHERE l.service IS NOT NULL),
         psv AS (
           SELECT protocol, port, array_agg(unit ORDER BY unit) AS svc FROM pu GROUP BY 1, 2),
         gp AS MATERIALIZED (
           SELECT m.asset_group_id, h.protocol, h.port, count(*) AS hosts
           FROM hp h JOIN console_host_group_membership m ON m.agent_id = h.agent_id
           GROUP BY m.asset_group_id, h.protocol, h.port),
         gsel AS (
           SELECT protocol || '/' || port AS key FROM gp WHERE asset_group_id::text = lower($7::text)),
         hsel AS (
           SELECT protocol || '/' || port AS key FROM hp WHERE agent_id = $10::text),
         p0 AS (
           SELECT h.protocol, h.port, h.protocol || '/' || h.port AS key,
                  count(*) AS hosts, count(*) FILTER (WHERE h.exposed) AS exposed_hosts,
                  bool_or(h.unowned) AS unowned
           FROM hp h GROUP BY h.protocol, h.port),
         p AS (
           SELECT p0.*, COALESCE(psv.svc, '{{}}') AS svc,
                  COALESCE(wk.added, 0) AS added, COALESCE(wk.removed, 0) AS removed,
                  array_remove(ARRAY[
                    CASE WHEN p0.key = ANY($14::text[]) AND p0.exposed_hosts > 0 THEN 'database_exposed' END,
                    CASE WHEN p0.key = ANY($15::text[]) AND p0.exposed_hosts > 0 THEN 'remote_admin_exposed' END,
                    CASE WHEN NOT p0.key = ANY($16::text[]) AND COALESCE(wk.added, 0) > 0 THEN 'new_unusual' END
                  ], NULL) AS look
           FROM p0 LEFT JOIN psv USING (protocol, port) LEFT JOIN wk USING (protocol, port)),
         m AS (SELECT p.* FROM p WHERE {all}),
         page AS (
           SELECT m.* FROM m ORDER BY {order} LIMIT $12 OFFSET $13),
         meta AS (
           SELECT jsonb_build_object(
             'total', (SELECT count(*) FROM m),
             'counts', jsonb_build_object(
               'exposure', jsonb_build_object(
                 'exposed', (SELECT count(*) FROM p WHERE {no_exposure} AND p.exposed_hosts > 0),
                 'local', (SELECT count(*) FROM p WHERE {no_exposure} AND p.exposed_hosts = 0)),
               'protocol', jsonb_build_object(
                 'tcp', (SELECT count(*) FROM p WHERE {no_protocol} AND p.protocol = 'tcp'),
                 'udp', (SELECT count(*) FROM p WHERE {no_protocol} AND p.protocol = 'udp')),
               'changes', jsonb_build_object(
                 'new', (SELECT count(*) FROM p WHERE {no_changes} AND p.added > 0),
                 'look', (SELECT count(*) FROM p WHERE {no_changes} AND cardinality(p.look) > 0)),
               'unowned', (SELECT count(*) FROM p WHERE {no_service} AND p.unowned),
               'services', (SELECT COALESCE(jsonb_agg(jsonb_build_array(s.unit, s.n) ORDER BY s.unit), '[]')
                            FROM (SELECT pu.unit, count(*) AS n FROM pu
                                  JOIN p ON p.protocol = pu.protocol AND p.port = pu.port
                                  WHERE {no_service} GROUP BY pu.unit) s),
               'groups', (SELECT COALESCE(jsonb_agg(jsonb_build_array(g.asset_group_id::text, g.name, g.kind, COALESCE(c.n, 0))), '[]')
                          FROM console_asset_groups g LEFT JOIN (
                            SELECT gp.asset_group_id AS gid, count(*) AS n
                            FROM gp JOIN p ON p.protocol = gp.protocol AND p.port = gp.port
                            WHERE {no_group} GROUP BY gp.asset_group_id) c ON c.gid = g.asset_group_id
                          WHERE c.n > 0
                             OR (g.asset_group_id::text = lower($7::text)
                                 AND ($1::boolean OR g.asset_group_id::text = ANY($2::text[]))))),
             'summary', jsonb_build_object(
               'exposed', (SELECT count(*) FROM m WHERE m.exposed_hosts > 0),
               'new_this_week', (SELECT count(*) FROM m WHERE m.added > 0),
               'need_a_look', (SELECT count(*) FROM m WHERE cardinality(m.look) > 0),
               'reporting_hosts', (SELECT count(*) FROM reach a
                                   WHERE a.status = 'active' AND a.services_at IS NOT NULL))
           ) AS meta)
         SELECT meta.meta, page.protocol, page.port, page.hosts, page.exposed_hosts, page.svc,
                page.unowned, page.added, page.removed, page.look,
                (SELECT COALESCE(jsonb_agg(jsonb_build_array(g.asset_group_id::text, g.name, g.kind, gp.hosts)
                                           ORDER BY gp.hosts DESC, lower(g.name), g.asset_group_id), '[]')
                 FROM gp JOIN console_asset_groups g ON g.asset_group_id = gp.asset_group_id
                 WHERE gp.protocol = page.protocol AND gp.port = page.port AND g.kind <> 'manual') AS groups
         FROM meta LEFT JOIN page ON true
         ORDER BY {order_page}",
        order_page = order.replace("m.", "page.")
    )
}
