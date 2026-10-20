//! The SQL of the Alarms list's one statement (plan rulings 2–5): the
//! `hosts` and `base` CTEs, each filter over a `base b` (or `cube b`) row,
//! "every filter except some", the `cube`, `per_host` and `counts` CTEs, the
//! sort keys and the statement. Only fixed internal strings are formatted
//! in; every value is bound.

use crate::{alarm_list::AlarmSort, host_list_sql::members};

/// One filter whose own condition the counts of its values leave out.
#[derive(Clone, Copy, PartialEq)]
enum Facet {
    State,
    Severity,
    Suppressed,
    Host,
    Group,
    Technique,
    Case,
    Assignee,
}

const FACETS: [Facet; 8] = [
    Facet::State,
    Facet::Severity,
    Facet::Suppressed,
    Facet::Host,
    Facet::Group,
    Facet::Technique,
    Facet::Case,
    Facet::Assignee,
];

/// One filter over a `base b` row (all but host and group also over a
/// `cube b` row); `$5`–`$12` and `$15` are the chosen values
/// (NULL for no filter; `$7` is true when suppressed alarms are shown; `$12` is
/// a user id as text, `$15` true for "unassigned").
fn filter(facet: Facet) -> &'static str {
    match facet {
        Facet::State => "($5::text IS NULL OR b.state = $5)",
        Facet::Severity => "($6::text IS NULL OR b.severity = $6)",
        Facet::Suppressed => "($7::boolean OR NOT b.suppressed)",
        Facet::Host => "($8::text IS NULL OR b.agent_id = $8)",
        Facet::Group => {
            "($9::text IS NULL OR b.agent_id IN (SELECT m.agent_id FROM members m WHERE m.gid = lower($9)))"
        }
        Facet::Technique => "($10::text IS NULL OR $10 = ANY(b.techniques))",
        Facet::Case => "($11::boolean IS NULL OR b.in_case = $11)",
        Facet::Assignee => {
            "(($12::text IS NULL AND NOT $15::boolean) OR ($15 AND b.assigned_to IS NULL)
              OR b.assigned_to = $12::text::uuid)"
        }
    }
}

/// Every chosen filter except those of `skip`.
fn except(skip: &[Facet]) -> String {
    FACETS
        .iter()
        .filter(|f| !skip.contains(f))
        .map(|f| filter(*f))
        .collect::<Vec<_>>()
        .join(" AND ")
}

/// CTEs `hosts` (agents in the scope `$1`,`$2`, with `alarms_health` set
/// when online at `$3` and reported) and `base`: their agent alarms matching
/// the search `$4`, narrowed to what the filters and sorts need. The
/// technique ids come from the rule-metadata index; `in_case`: an open case
/// holds the alarm (at most one does).
///
/// The scope is `agent_visibility`'s rule read from `members` (one pass over
/// every agent, pinned to `console_host_in_group` by the Hosts list tests):
/// calling `console_host_in_group` per agent and scope group cost 0.9 s at
/// 20,000 agents and two groups.
fn base() -> &'static str {
    "hosts AS MATERIALIZED (
  SELECT a.agent_id, a.hostname,
         CASE WHEN a.status = 'active' AND a.health_at IS NOT NULL
                   AND agent_seen_at(a.agent_id, a.last_seen_at) >= $3 THEN a.health -> 'alarms' END AS alarms_health
  FROM agents a
  WHERE $1::boolean OR (a.status <> 'imported' AND EXISTS (
          SELECT 1 FROM members m WHERE m.agent_id = a.agent_id AND m.gid = ANY($2::text[])))),
base AS MATERIALIZED (
  SELECT al.id, al.first_seen_day, al.agent_id, al.severity, al.state, al.suppressed_by IS NOT NULL AS suppressed,
         al.assigned_to, al.count, al.first_seen, al.last_seen, COALESCE(rm.techniques, '{}') AS techniques,
         ci.case_id IS NOT NULL AS in_case
  FROM alarms al JOIN hosts h ON h.agent_id = al.agent_id
  LEFT JOIN console_rule_meta rm
    ON rm.rule_set_id = al.rule_set_id AND rm.rule_set_version = al.rule_set_version
   AND rm.rule_id = al.rule_id AND rm.rule_version = al.rule_version
  LEFT JOIN case_items ci ON ci.kind = 'alarm' AND ci.active AND ci.ref = al.id::text
  WHERE al.source = 'agent'
    AND ($4::text IS NULL OR strpos(lower(al.message), lower($4)) > 0
         OR strpos(lower(al.rule_id), lower($4)) > 0 OR strpos(lower(h.hostname), lower($4)) > 0
         OR strpos(lower(al.process ->> 'exe'), lower($4)) > 0
         OR strpos(lower(al.ancestors -> 0 ->> 'exe'), lower($4)) > 0))"
}

/// CTEs `cube`: `base` rows within the host and group filters, counted per
/// combination of the other facets' keys (a few hundred rows, so each
/// facet's counts are a sum over it); `per_host`: per host in `base`, its
/// alarms matching every filter but the group's (for group counts) and its
/// open alarms matching every filter (for the summary's alarms-off part).
fn rollups() -> String {
    let host_group = [filter(Facet::Host), filter(Facet::Group)].join(" AND ");
    let but_group = except(&[Facet::Group]);
    let open = except(&[Facet::State]);
    format!(
        "cube AS MATERIALIZED (
  SELECT b.state, b.severity, b.suppressed, b.in_case, b.assigned_to, b.techniques, count(*) AS n
  FROM base b WHERE {host_group}
  GROUP BY b.state, b.severity, b.suppressed, b.in_case, b.assigned_to, b.techniques),
per_host AS MATERIALIZED (
  SELECT b.agent_id, count(*) FILTER (WHERE {but_group}) AS n,
         count(*) FILTER (WHERE {open} AND b.state = 'open') AS open
  FROM base b GROUP BY b.agent_id)"
    )
}

/// CTE `counts` (facet, key, name, kind, n): each facet's values with every
/// other filter applied, from `cube` (and `per_host` for groups). Group,
/// technique and person values come from alarms in `base`, so none is named
/// from a host out of reach; the chosen group is added with 0 when the
/// scope reaches it. The host filter has no value list (the page shows the
/// chosen host as a chip).
fn counts() -> String {
    let but = |f: Facet| except(&[f, Facet::Host, Facet::Group]);
    let [state, severity, suppressed, technique, case, assignee] = [
        Facet::State,
        Facet::Severity,
        Facet::Suppressed,
        Facet::Technique,
        Facet::Case,
        Facet::Assignee,
    ]
    .map(but);
    format!(
        "counts AS (
  SELECT 'state' AS facet, b.state AS key, NULL::text AS name, NULL::text AS kind,
         COALESCE(sum(b.n) FILTER (WHERE {state}), 0)::bigint AS n
  FROM cube b GROUP BY b.state
  UNION ALL
  SELECT 'severity', b.severity, NULL, NULL, COALESCE(sum(b.n) FILTER (WHERE {severity}), 0)::bigint
  FROM cube b GROUP BY b.severity
  UNION ALL
  SELECT 'suppressed', s.key, NULL, NULL, s.n
  FROM (SELECT COALESCE(sum(b.n) FILTER (WHERE {suppressed} AND NOT b.suppressed), 0)::bigint AS hidden,
               COALESCE(sum(b.n) FILTER (WHERE {suppressed}), 0)::bigint AS shown FROM cube b) c
  CROSS JOIN LATERAL (VALUES ('hidden', c.hidden), ('shown', c.shown)) s(key, n)
  UNION ALL
  SELECT 'case', CASE WHEN b.in_case THEN 'yes' ELSE 'no' END, NULL, NULL,
         COALESCE(sum(b.n) FILTER (WHERE {case}), 0)::bigint
  FROM cube b GROUP BY b.in_case
  UNION ALL
  SELECT 'technique', t.id, NULL, NULL, COALESCE(sum(b.n) FILTER (WHERE {technique}), 0)::bigint
  FROM cube b CROSS JOIN unnest(b.techniques) t(id) GROUP BY t.id
  UNION ALL
  SELECT 'unassigned', 'unassigned', NULL, NULL,
         COALESCE(sum(b.n) FILTER (WHERE b.assigned_to IS NULL AND {assignee}), 0)::bigint
  FROM cube b
  UNION ALL
  SELECT 'person', u.user_id::text, u.display_name, NULL, c.n
  FROM (SELECT b.assigned_to, COALESCE(sum(b.n) FILTER (WHERE {assignee}), 0)::bigint AS n
        FROM cube b WHERE b.assigned_to IS NOT NULL GROUP BY b.assigned_to) c
  JOIN console_users u ON u.user_id = c.assigned_to
  UNION ALL
  SELECT 'group', g.asset_group_id::text, g.name, g.kind, COALESCE(c.n, 0)::bigint
  FROM console_asset_groups g LEFT JOIN (
    SELECT m.gid, sum(p.n) AS n FROM members m JOIN per_host p ON p.agent_id = m.agent_id GROUP BY m.gid) c
    ON c.gid = g.asset_group_id::text
  WHERE c.gid IS NOT NULL
     OR (g.asset_group_id::text = lower($9) AND ($1::boolean OR g.asset_group_id::text = ANY($2::text[]))))"
    )
}

/// The sort keys over a `filtered f` row, ending in the id tie-break.
fn order(sort: AlarmSort, descending: bool) -> String {
    let dir = if descending { "DESC" } else { "ASC" };
    let key = match sort {
        AlarmSort::LastSeen => "f.last_seen",
        AlarmSort::FirstSeen => "f.first_seen",
        AlarmSort::Count => "f.count",
        AlarmSort::Severity => {
            "array_position(ARRAY['info', 'low', 'medium', 'high', 'critical'], f.severity)"
        }
    };
    format!("{key} {dir}, f.id {dir}")
}

/// The open matching alarms per host alarm health, its counters zeroed so
/// hosts in the same condition group together; the caller applies
/// `alarms_status` to each.
const HEALTH: &str = "(SELECT COALESCE(jsonb_agg(jsonb_build_array(x.health, x.n)), '[]') FROM (
      SELECT (SELECT jsonb_object_agg(e.key, CASE WHEN jsonb_typeof(e.value) = 'number' THEN '0'::jsonb
                                                  ELSE e.value END)
              FROM jsonb_each(h.alarms_health) e) AS health, sum(p.open) AS n
      FROM per_host p JOIN hosts h ON h.agent_id = p.agent_id
      WHERE p.open > 0 AND jsonb_typeof(h.alarms_health) = 'object'
      GROUP BY 1) x)";

/// The statement: `meta` holds the total, summary and counts as JSON on the
/// first row only (the summary counts open alarms whatever the state filter); the page rows (`$13` limit, `$14` offset of `base` with
/// every filter) are read back from `alarms`. An empty page still returns
/// one row, with the meta and no alarm.
pub(crate) fn statement(sort: AlarmSort, descending: bool) -> String {
    let all = except(&[]);
    let in_cube = except(&[Facet::Host, Facet::Group]);
    let in_cube_any_state = except(&[Facet::State, Facet::Host, Facet::Group]);
    format!(
        "WITH {members}, {base}, {rollups}, {counts},
meta AS (
  SELECT jsonb_build_object(
    'total', COALESCE(sum(b.n) FILTER (WHERE {in_cube}), 0),
    'open', COALESCE(sum(b.n) FILTER (WHERE {in_cube_any_state} AND b.state = 'open'), 0),
    'severe', COALESCE(sum(b.n) FILTER (WHERE {in_cube_any_state} AND b.state = 'open'
                                        AND b.severity IN ('critical', 'high')), 0),
    'health', {HEALTH},
    'counts', (SELECT COALESCE(jsonb_agg(jsonb_build_array(facet, key, name, kind, n)), '[]') FROM counts)) AS meta
  FROM cube b),
page AS (SELECT f.*, row_number() OVER (ORDER BY {order}) AS ord
         FROM (SELECT f.* FROM (SELECT * FROM base b WHERE {all}) f ORDER BY {order} LIMIT $13 OFFSET $14) f)
SELECT CASE WHEN p.ord IS NOT DISTINCT FROM (SELECT min(ord) FROM page) THEN m.meta END,
       p.id, p.agent_id, a.hostname, a.os_family, console_distribution_name(a.distribution),
       al.rule_set_id, al.rule_id, p.severity, al.message, al.process ->> 'exe', al.ancestors -> 0 ->> 'exe',
       p.techniques, p.count, p.first_seen, p.last_seen, p.state,
       p.assigned_to::text, u.display_name, cs.case_id::text, cs.number, al.suppressed_by
FROM meta m LEFT JOIN page p ON true
LEFT JOIN alarms al ON al.id = p.id AND al.first_seen_day = p.first_seen_day
LEFT JOIN agents a ON a.agent_id = p.agent_id
LEFT JOIN console_users u ON u.user_id = p.assigned_to
LEFT JOIN case_items ci ON ci.kind = 'alarm' AND ci.active AND ci.ref = p.id::text
LEFT JOIN cases cs ON cs.case_id = ci.case_id
ORDER BY p.ord",
        base = base(),
        members = members("agents"),
        rollups = rollups(),
        counts = counts(),
        order = order(sort, descending),
    )
}
