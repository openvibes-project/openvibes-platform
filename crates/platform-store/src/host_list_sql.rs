//! The SQL of the Hosts list's one statement (plan rulings 3–7): the
//! `base` CTE, each filter over a `base b` row, "every filter except one",
//! group membership, the `counts` CTE, the sort keys and the statement.
//! Only fixed internal strings are formatted in; every value is bound.

use crate::{console_read::agent_visibility, host_list::HostSort};

/// One filter whose own condition the counts of its values leave out.
#[derive(Clone, Copy, PartialEq)]
enum Facet {
    Status,
    Os,
    Group,
    Label,
    Problems,
    Agent,
}

const FACETS: [Facet; 6] = [
    Facet::Status,
    Facet::Os,
    Facet::Group,
    Facet::Label,
    Facet::Problems,
    Facet::Agent,
];

/// No visible problem of any kind, on a host where at least one kind is in reach.
const NONE_OPEN: &str = "(b.open_alarms IS NOT NULL OR b.critical IS NOT NULL OR b.failing IS NOT NULL)
    AND COALESCE(b.open_alarms, 0) = 0 AND COALESCE(b.critical, 0) = 0 AND COALESCE(b.failing, 0) = 0";

/// One filter over a `base b` row; `$13`–`$18` are the chosen values (NULL
/// for no filter).
fn filter(facet: Facet) -> String {
    match facet {
        Facet::Status => "($13::text IS NULL OR b.status = $13)".into(),
        Facet::Os => "($14::text IS NULL OR b.os_family = $14)".into(),
        Facet::Group => "($15::text IS NULL OR b.agent_id IN (SELECT m.agent_id FROM members m
                                                         WHERE m.gid = lower($15)))"
            .into(),
        Facet::Label => "($16::text IS NULL OR EXISTS (SELECT 1 FROM console_host_labels fl
                          WHERE fl.agent_id = b.agent_id AND fl.label = $16))"
            .into(),
        Facet::Problems => format!(
            "($17::text IS NULL OR ($17 = 'critical' AND b.critical > 0)
              OR ($17 = 'open_alarms' AND b.open_alarms > 0) OR ($17 = 'none_open' AND {NONE_OPEN}))"
        ),
        Facet::Agent => "($18::text IS NULL OR ($18 = 'older' AND b.older) OR ($18 = 'latest' AND NOT b.older))".into(),
    }
}

/// Every chosen filter except `skip`'s own.
fn except(skip: Option<Facet>) -> String {
    FACETS
        .iter()
        .filter(|f| Some(**f) != skip)
        .map(|f| filter(*f))
        .collect::<Vec<_>>()
        .join(" AND ")
}

/// CTE `members` (agent_id, gid): which hosts of the CTE `hosts` (any CTE
/// with an `agent_id` column) are in which group, read from the stored
/// membership (migration 61), which triggers keep equal to the rule of
/// `console_host_in_group` (migration 53).
pub(crate) fn members(hosts: &str) -> String {
    format!(
        "members AS MATERIALIZED (
  SELECT m.agent_id, m.asset_group_id::text AS gid
  FROM {hosts} b JOIN console_host_group_membership m ON m.agent_id = b.agent_id)"
    )
}

/// CTE `counts` (facet, key, name, kind, n): each facet's values over
/// `base` with every other filter applied. Group and label values come from
/// hosts in `base`, so none is named from a host out of reach; the chosen
/// group is added with 0 when the hosts scope reaches it (global, or one of
/// its groups), the chosen label when it is on a host in the hosts scope.
fn counts() -> String {
    let [status, os, group, label, problems, agent] = FACETS.map(|f| except(Some(f)));
    let visible = agent_visibility("a.agent_id", "$2", "$3");
    format!(
        "counts AS (
  SELECT 'status' AS facet, b.status AS key, NULL::text AS name, NULL::text AS kind, count(*) AS n
  FROM base b WHERE {status} GROUP BY b.status
  UNION ALL
  SELECT 'os', b.os_family, NULL, NULL, count(*)
  FROM base b WHERE b.os_family IS NOT NULL AND {os} GROUP BY b.os_family
  UNION ALL
  SELECT 'problems', p.key, NULL, NULL, count(*)
  FROM base b CROSS JOIN LATERAL (VALUES ('critical', b.critical > 0), ('open_alarms', b.open_alarms > 0),
                                         ('none_open', {NONE_OPEN})) p(key, hit)
  WHERE p.hit AND {problems} GROUP BY p.key
  UNION ALL
  SELECT 'agent', CASE WHEN b.older THEN 'older' ELSE 'latest' END, NULL, NULL, count(*)
  FROM base b WHERE b.older IS NOT NULL AND {agent} GROUP BY 2
  UNION ALL
  SELECT 'group', g.asset_group_id::text, g.name, g.kind, COALESCE(c.n, 0)
  FROM console_asset_groups g LEFT JOIN (
    SELECT m.gid, count(*) FILTER (WHERE {group}) AS n
    FROM members m JOIN base b ON b.agent_id = m.agent_id GROUP BY m.gid) c
    ON c.gid = g.asset_group_id::text
  WHERE c.n > 0 OR (g.asset_group_id::text = lower($15)
                    AND (c.gid IS NOT NULL OR $2::boolean OR g.asset_group_id::text = ANY($3::text[])))
  UNION ALL
  SELECT 'label', x.label, NULL, NULL, x.n FROM (
    SELECT l.label, count(*) FILTER (WHERE {label}) AS n, l.label = $16 AS chosen,
           row_number() OVER (PARTITION BY l.label = $16 ORDER BY count(*) FILTER (WHERE {label}) DESC,
                                                         l.label COLLATE \"C\") AS rank
    FROM base b JOIN console_host_labels l ON l.agent_id = b.agent_id GROUP BY l.label) x
  WHERE x.chosen IS TRUE OR (x.n > 0 AND x.rank <= 50)
  UNION ALL
  SELECT 'label', $16, NULL, NULL, 0
  WHERE $16::text IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM base b JOIN console_host_labels l ON l.agent_id = b.agent_id
                    WHERE l.label = $16)
    AND EXISTS (SELECT 1 FROM agents a JOIN console_host_labels l ON l.agent_id = a.agent_id
                WHERE l.label = $16 AND {visible}))"
    )
}

/// CTE `base`: hosts in the hosts scope (`$2`,`$3`) matching the search
/// (`$11`: name contains, agent id or address starts with; `$12` CIDR), with status (`$1` online threshold), agent age
/// (`$10` latest) and each problem count gated by its own scope (`$4`–`$9`).
fn base() -> String {
    let hosts = agent_visibility("a.agent_id", "$2", "$3");
    let alarms = agent_visibility("a.agent_id", "$4", "$5");
    let vulns = agent_visibility("a.agent_id", "$6", "$7");
    let compliance = agent_visibility("a.agent_id", "$8", "$9");
    format!(
        "base AS MATERIALIZED (
  SELECT a.agent_id, a.hostname, a.last_address, a.os_id, a.os_version, a.distribution,
         a.os_family, a.scanner_version, s.seen, a.health_at, a.health -> 'alarms' AS alarms_health,
         CASE WHEN a.status = 'imported' THEN 'imported' WHEN a.status = 'revoked' THEN 'revoked'
              WHEN s.seen IS NULL OR s.seen < $1 THEN 'offline' ELSE 'online' END AS status,
         console_version_older(a.scanner_version, $10) AS older,
         CASE WHEN {alarms} THEN (SELECT count(*) FROM alarms al WHERE al.agent_id = a.agent_id
                                    AND al.state = 'open' AND al.source = 'agent') END AS open_alarms,
         CASE WHEN {vulns} THEN COALESCE((SELECT v.critical FROM host_listed_critical v
                                           WHERE v.agent_id = a.agent_id), 0)::bigint END AS critical,
         CASE WHEN {compliance} THEN (SELECT count(*) FROM current_findings cf
                                        LEFT JOIN console_finding_triage ct USING (agent_id, rule_set_id, rule_id)
                                        WHERE cf.agent_id = a.agent_id AND cf.ended_at IS NULL
                                          AND COALESCE(ct.state, 'open') = 'open') END AS failing
  FROM agents a CROSS JOIN LATERAL (SELECT agent_seen_at(a.agent_id, a.last_seen_at) AS seen) s
  WHERE {hosts}
    AND ($11::text IS NULL OR strpos(lower(a.hostname), lower($11)) > 0
         OR starts_with(lower(a.agent_id), lower($11))
         OR starts_with(host(a.last_address), $11) OR a.last_address <<= $12::text::inet))"
    )
}

/// The sort keys over a `filtered f` row, ending in the agent-id tie-break.
fn order(sort: HostSort, descending: bool) -> String {
    let dir = if descending { "DESC" } else { "ASC" };
    let key = match sort {
        HostSort::Host => format!("COALESCE(lower(f.hostname), '') {dir}"),
        HostSort::Heartbeat => format!("f.seen {dir} NULLS LAST"),
        HostSort::Version => format!(
            "console_version_parts(f.scanner_version) {dir} NULLS LAST,
             strpos(split_part(f.scanner_version, '+', 1), '-') = 0 {dir}"
        ),
        HostSort::Problems => format!(
            "COALESCE(f.open_alarms, 0) + COALESCE(f.critical, 0) + COALESCE(f.failing, 0) {dir}"
        ),
    };
    format!("{key}, f.agent_id")
}

/// The statement: `filtered` is `base` with every filter; `meta` holds the
/// total, summary and counts as JSON on the first row only; the page rows
/// (`$19` limit, `$20` offset) carry their groups and labels. An empty page
/// still returns one row, with the meta and no host.
pub(crate) fn statement(sort: HostSort, descending: bool) -> String {
    format!(
        "WITH {base}, {members}, {counts},
filtered AS (SELECT * FROM base b WHERE {all}),
meta AS (
  SELECT jsonb_build_object(
    'total', count(*), 'online', count(*) FILTER (WHERE status = 'online'),
    'older', count(*) FILTER (WHERE older), 'critical', count(*) FILTER (WHERE critical > 0),
    'counts', (SELECT COALESCE(jsonb_agg(jsonb_build_array(facet, key, name, kind, n)), '[]') FROM counts)) AS meta
  FROM filtered),
page AS (SELECT f.*, row_number() OVER (ORDER BY {order}) AS ord FROM filtered f ORDER BY ord LIMIT $19 OFFSET $20)
SELECT CASE WHEN p.ord IS NOT DISTINCT FROM (SELECT min(ord) FROM page) THEN m.meta END,
       p.agent_id, p.hostname, host(p.last_address), p.os_id, p.os_version,
       console_distribution_name(p.distribution), p.os_family, p.status, p.seen,
       gr.ids, gr.names, gr.kinds, gr.n,
       ARRAY(SELECT l.label FROM console_host_labels l WHERE l.agent_id = p.agent_id ORDER BY l.label COLLATE \"C\"),
       p.open_alarms, p.critical, p.failing, p.scanner_version, p.older,
       p.health_at IS NOT NULL, p.alarms_health
FROM meta m LEFT JOIN page p ON true
LEFT JOIN LATERAL (
  SELECT (array_agg(g.asset_group_id::text ORDER BY lower(g.name), g.asset_group_id))[1:2] AS ids,
         (array_agg(g.name ORDER BY lower(g.name), g.asset_group_id))[1:2] AS names,
         (array_agg(g.kind ORDER BY lower(g.name), g.asset_group_id))[1:2] AS kinds, count(*) AS n
  FROM console_asset_groups g WHERE console_host_in_group(p.agent_id, g.asset_group_id)) gr ON true
ORDER BY p.ord",
        base = base(),
        members = members("base"),
        counts = counts(),
        all = except(None),
        order = order(sort, descending),
    )
}
