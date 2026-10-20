//! The Hosts list's filters and per-value counts (plan rulings 3–5), used
//! by `host_list`'s one statement: each filter as SQL over a `base b` row,
//! "every filter except one", group membership and the `counts` CTE.

/// One filter whose own condition the counts of its values leave out.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Facet {
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
pub(crate) fn except(skip: Option<Facet>) -> String {
    FACETS
        .iter()
        .filter(|f| Some(**f) != skip)
        .map(|f| filter(*f))
        .collect::<Vec<_>>()
        .join(" AND ")
}

/// CTEs `conds` and `members` (agent_id, gid): which hosts in `base` are
/// in which group, in one pass. The same rule as `console_host_in_group`
/// (migration 53): active hosts only; a manual group holds its picked
/// hosts; a rule or automatic group holds a host when it has conditions and
/// every one holds. `host_list` tests pin the two to the same answers.
// ponytail: evaluated per (host, rule condition) on every list request;
// 20,000 hosts and 20 groups measured in console-read.md. Past that,
// materialise membership in a table refreshed on fact and rule changes.
pub(crate) fn members() -> String {
    "conds AS MATERIALIZED (
  SELECT c.asset_group_id, c.field, c.negate, c.vals, console_condition_likes(c.vals) AS likes,
         CASE WHEN c.field = 'ip' THEN c.vals::inet[] END AS nets
  FROM console_host_group_conditions c),
members AS MATERIALIZED (
  SELECT m.agent_id, m.asset_group_id::text AS gid
  FROM base b JOIN console_host_group_members m ON m.agent_id = b.agent_id
  JOIN console_asset_groups g ON g.asset_group_id = m.asset_group_id AND g.kind = 'manual'
  WHERE b.status IN ('online', 'offline')
  UNION ALL
  SELECT a.agent_id, g.asset_group_id::text
  FROM base b JOIN agents a ON a.agent_id = b.agent_id
  CROSS JOIN console_asset_groups g
  WHERE a.status = 'active' AND g.kind <> 'manual'
    AND EXISTS (SELECT 1 FROM conds c WHERE c.asset_group_id = g.asset_group_id)
    AND NOT EXISTS (SELECT 1 FROM conds c WHERE c.asset_group_id = g.asset_group_id
                      AND NOT COALESCE(console_condition_holds_prepared(a, c.field, c.negate, c.vals,
                                                                        c.likes, c.nets), false)))"
        .into()
}

/// CTE `counts` (facet, key, name, kind, n): each facet's values over
/// `base` with every other filter applied. Group and label values come only
/// from hosts in `base`, so none is named from a host out of reach.
pub(crate) fn counts() -> String {
    let [status, os, group, label, problems, agent] = FACETS.map(|f| except(Some(f)));
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
  SELECT 'group', m.gid, g.name, g.kind, count(*) FILTER (WHERE {group})
  FROM members m JOIN base b ON b.agent_id = m.agent_id
  JOIN console_asset_groups g ON g.asset_group_id::text = m.gid
  GROUP BY m.gid, g.name, g.kind
  HAVING count(*) FILTER (WHERE {group}) > 0 OR m.gid = lower($15)
  UNION ALL
  SELECT 'label', x.label, NULL, NULL, x.n FROM (
    SELECT l.label, count(*) FILTER (WHERE {label}) AS n, l.label = $16 AS chosen,
           row_number() OVER (PARTITION BY l.label = $16 ORDER BY count(*) FILTER (WHERE {label}) DESC,
                                                         l.label COLLATE \"C\") AS rank
    FROM base b JOIN console_host_labels l ON l.agent_id = b.agent_id GROUP BY l.label) x
  WHERE x.chosen IS TRUE OR (x.n > 0 AND x.rank <= 50))"
    )
}
