//! The SQL of the Cases list's one statement (step 5d rulings 2, 4, 6–10).
//! `vi` holds the items the viewer sees ([`item_visible`]), `ag` their
//! counts per case (`hosted`: those in scope, which decide visibility), `cg` each case's groups through those items' hosts;
//! `r` is one row per case the viewer sees (`case_visible`, its item test
//! read from `ag`), and every
//! filter, count, the summary and the page read `r`. Only fixed internal
//! strings are formatted in; every value is bound.
//!
//! Parameters: `$1` global scope, `$2` scope group ids, `$3` viewer user id
//! (text), `$4` search, `$5` the case number in it, `$6` status, `$7`
//! severity, `$8` assignee user id (text), `$9` unassigned, `$10` contains
//! (an item kind), `$11` host, `$12` group, `$13` updated, `$14` now, `$15`
//! limit, `$16` offset.

use crate::{
    case_list::CaseSort,
    console_cases::{blocking_item, case_visible_with, item_visible},
    console_read::agent_visibility,
};

/// Hosts a row names; `host_count` has them all.
const MAX_HOSTS: i64 = 5;

/// The item kinds that take an outcome (ruling 2).
const TAKES: &str = "('alarm', 'compliance_finding', 'vulnerability')";

/// Updated today: since midnight UTC of `$14`, the same day for every viewer.
const TODAY: &str =
    "r.updated_at >= date_trunc('day', $14::timestamptz AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'";
/// Updated within the last 7 days.
const WEEK: &str = "r.updated_at >= $14::timestamptz - interval '7 days'";
/// Not updated for 7 days or more.
const QUIET: &str = "r.updated_at < $14::timestamptz - interval '7 days'";

/// A filter whose own condition the counts of its values leave out. Host
/// and search narrow every count.
#[derive(Clone, Copy, PartialEq)]
enum Facet {
    Status,
    Severity,
    Assignee,
    Contains,
    Updated,
    Group,
}

const FACETS: [Facet; 6] = [
    Facet::Status,
    Facet::Severity,
    Facet::Assignee,
    Facet::Contains,
    Facet::Updated,
    Facet::Group,
];

fn filter(facet: Facet) -> String {
    match facet {
        Facet::Status => {
            "($6::text = 'all' OR ($6 = 'active' AND r.status <> 'closed') OR r.status = $6)".into()
        }
        Facet::Severity => "($7::text IS NULL OR r.severity = $7)".into(),
        Facet::Assignee => {
            "(($8::text IS NULL AND NOT $9::boolean) OR ($9 AND r.assignee_user_id IS NULL)
          OR r.assignee_user_id = $8::text::uuid)"
                .into()
        }
        Facet::Contains => "($10::text IS NULL OR CASE $10 WHEN 'alarm' THEN r.alarms > 0
          WHEN 'vulnerability' THEN r.vulnerabilities > 0 ELSE r.findings > 0 END)"
            .into(),
        Facet::Updated => format!(
            "($13::text IS NULL OR CASE $13 WHEN 'today' THEN {TODAY} WHEN 'week' THEN {WEEK} ELSE {QUIET} END)"
        ),
        Facet::Group => "($12::text IS NULL OR r.in_group)".into(),
    }
}

/// Every chosen filter, the host and the search, except those of `skip`.
fn except(skip: &[Facet]) -> String {
    FACETS
        .iter()
        .filter(|f| !skip.contains(f))
        .map(|f| filter(*f))
        .chain(["($11::text IS NULL OR r.on_host)".into(), "r.m_q".into()])
        .collect::<Vec<_>>()
        .join(" AND ")
}

/// `vi`, `ag`, `cg` and `r`. A case without a visible item counts zero of
/// everything and is on no host or group.
fn base() -> String {
    let blocking = blocking_item();
    let (item, case) = (
        item_visible("i"),
        case_visible_with("c", "COALESCE(ag.hosted, 0) > 0"),
    );
    let kind = |k: &str| format!("count(*) FILTER (WHERE kind = '{k}')");
    let (alarms, findings, vulns, hosts, software) = (
        kind("alarm"),
        kind("compliance_finding"),
        kind("vulnerability"),
        kind("host"),
        kind("software"),
    );
    format!(
        "vi AS MATERIALIZED (
  SELECT i.case_id, i.kind, i.agent_id, i.outcome FROM case_items i WHERE {item}),
ag AS MATERIALIZED (
  SELECT case_id, {alarms} AS alarms, {findings} AS findings, {vulns} AS vulnerabilities,
         {hosts} AS host_items, {software} AS software,
         count(*) FILTER (WHERE kind IN {TAKES}) AS takes,
         count(*) FILTER (WHERE kind IN {TAKES} AND outcome IS NOT NULL) AS done,
         count(*) FILTER (WHERE agent_id IS NOT NULL) AS hosted,
         COALESCE(bool_or(agent_id = $11::text), false) AS on_host
  FROM vi GROUP BY 1),
cg AS MATERIALIZED (
  SELECT DISTINCT vi.case_id, m.asset_group_id::text AS gid
  FROM vi JOIN console_host_group_membership m ON m.agent_id = vi.agent_id),
r AS MATERIALIZED (
  SELECT c.case_id, c.number, c.title, c.status, c.severity, c.assignee_user_id, c.opened_by_user_id,
         c.created_at, c.updated_at,
         COALESCE(ag.alarms, 0) AS alarms, COALESCE(ag.findings, 0) AS findings,
         COALESCE(ag.vulnerabilities, 0) AS vulnerabilities, COALESCE(ag.host_items, 0) AS host_items,
         COALESCE(ag.software, 0) AS software, COALESCE(ag.takes, 0) AS takes, COALESCE(ag.done, 0) AS done,
         COALESCE(ag.on_host, false) AS on_host, gc.case_id IS NOT NULL AS in_group,
         (c.status <> 'closed' AND NOT EXISTS (SELECT 1 FROM case_items i
                                               WHERE i.case_id = c.case_id AND {blocking})) AS ready,
         ($4::text IS NULL OR c.number = $5::bigint OR strpos(lower(c.title), lower($4)) > 0
          OR strpos(lower(ou.display_name), lower($4)) > 0 OR strpos(lower(ou.username), lower($4)) > 0) AS m_q
  FROM cases c JOIN console_users ou ON ou.user_id = c.opened_by_user_id
  LEFT JOIN ag ON ag.case_id = c.case_id
  LEFT JOIN (SELECT DISTINCT case_id FROM cg WHERE cg.gid = lower($12::text)) gc ON gc.case_id = c.case_id
  WHERE {case})"
    )
}

/// CTE `counts`: every facet's values, each with the other filters applied.
/// People are those assigned a case the viewer sees; groups those holding a
/// host the viewer sees, plus the chosen one when the scope reaches it.
fn counts() -> String {
    let [status, severity, assignee, contains, updated, group] = FACETS.map(|f| except(&[f]));
    let hosts = agent_visibility("a.agent_id", "$1", "$2");
    format!(
        "counts AS (
  SELECT jsonb_build_object(
    'status', (SELECT jsonb_build_object('active', count(*) FILTER (WHERE r.status <> 'closed'),
                 'open', count(*) FILTER (WHERE r.status = 'open'),
                 'investigating', count(*) FILTER (WHERE r.status = 'investigating'),
                 'closed', count(*) FILTER (WHERE r.status = 'closed'), 'all', count(*))
               FROM r WHERE {status}),
    'severity', (SELECT COALESCE(jsonb_object_agg(s.severity, s.n), '{{}}')
                 FROM (SELECT r.severity, count(*) AS n FROM r WHERE {severity} GROUP BY 1) s),
    'contains', (SELECT jsonb_build_object('alarms', count(*) FILTER (WHERE r.alarms > 0),
                   'vulnerabilities', count(*) FILTER (WHERE r.vulnerabilities > 0),
                   'findings', count(*) FILTER (WHERE r.findings > 0))
                 FROM r WHERE {contains}),
    'updated', (SELECT jsonb_build_object('today', count(*) FILTER (WHERE {TODAY}),
                  'week', count(*) FILTER (WHERE {WEEK}), 'quiet', count(*) FILTER (WHERE {QUIET}))
                FROM r WHERE {updated}),
    'unassigned', (SELECT count(*) FROM r WHERE {assignee} AND r.assignee_user_id IS NULL),
    'people', (SELECT COALESCE(jsonb_agg(jsonb_build_array(u.user_id::text, u.display_name, p.n)), '[]')
               FROM (SELECT r.assignee_user_id AS id, count(*) FILTER (WHERE {assignee}) AS n
                     FROM r WHERE r.assignee_user_id IS NOT NULL GROUP BY 1) p
               JOIN console_users u ON u.user_id = p.id),
    'groups', (SELECT COALESCE(jsonb_agg(jsonb_build_array(g.asset_group_id::text, g.name, g.kind, COALESCE(n.n, 0))), '[]')
               FROM console_asset_groups g
               LEFT JOIN (SELECT cg.gid, count(*) AS n FROM cg JOIN r ON r.case_id = cg.case_id
                          WHERE {group} GROUP BY 1) n ON n.gid = g.asset_group_id::text
               WHERE g.asset_group_id IN (SELECT m.asset_group_id FROM console_host_group_membership m
                                          JOIN agents a ON a.agent_id = m.agent_id WHERE {hosts})
                  OR (g.asset_group_id::text = lower($12) AND ($1::boolean OR g.asset_group_id::text = ANY($2::text[]))))
  ) AS counts)"
    )
}

/// CTE `summary` (ruling 10): of the cases matching every filter but the
/// status's, those not closed: open, investigating, unassigned, and ready
/// to close by close's own rule (`r.ready`: no item, visible or hidden,
/// is a [`blocking_item`]; only that boolean per case is revealed).
fn summary() -> String {
    let rows = except(&[Facet::Status]);
    format!(
        "summary AS (
  SELECT jsonb_build_object('open', count(*) FILTER (WHERE r.status = 'open'),
           'investigating', count(*) FILTER (WHERE r.status = 'investigating'),
           'unassigned', count(*) FILTER (WHERE r.assignee_user_id IS NULL),
           'ready_to_close', count(*) FILTER (WHERE r.ready)) AS summary
  FROM r WHERE r.status <> 'closed' AND {rows})"
    )
}

/// The sort key over a `p` row, then the case id in the same direction.
fn order(sort: CaseSort, descending: bool) -> String {
    let dir = if descending { "DESC" } else { "ASC" };
    let key = match sort {
        CaseSort::Updated => "p.updated_at",
        CaseSort::Severity => "array_position(ARRAY['low','medium','high','critical'], p.severity)",
        CaseSort::Number => "p.number",
        CaseSort::Opened => "p.created_at",
    };
    format!("{key} {dir}, p.case_id {dir}")
}

/// The statement: the meta (total, counts, summary) as JSON on the first
/// row only, then the page with its opener, assignee, latest note (ruling 9:
/// the newest `note` event, its first 120 characters) and the first
/// [`MAX_HOSTS`] visible hosts by name, with their count. An empty page still returns one row, with the meta and no case.
pub(crate) fn statement(sort: CaseSort, descending: bool) -> String {
    let all = except(&[]);
    let order = order(sort, descending);
    let item = crate::console_cases::item_in_scope("i");
    format!(
        "WITH {base}, {counts}, {summary},
meta AS (
  SELECT jsonb_build_object('total', (SELECT count(*) FROM r WHERE {all}),
                            'counts', (SELECT counts FROM counts),
                            'summary', (SELECT summary FROM summary)) AS meta),
page AS (
  SELECT p.*, row_number() OVER (ORDER BY {order}) AS ord
  FROM (SELECT * FROM r WHERE {all}) p ORDER BY {order} LIMIT $15 OFFSET $16)
SELECT CASE WHEN p.ord IS NOT DISTINCT FROM (SELECT min(ord) FROM page) THEN m.meta END,
       p.case_id::text, p.number, p.title, p.status, p.severity,
       p.opened_by_user_id::text, ou.username, ou.display_name,
       p.assignee_user_id::text, au.username, au.display_name, n.body, n.at, h.hosts,
       p.alarms, p.findings, p.vulnerabilities, p.host_items, p.software, p.takes, p.done, p.updated_at,
       h.host_count
FROM meta m LEFT JOIN page p ON true
LEFT JOIN console_users ou ON ou.user_id = p.opened_by_user_id
LEFT JOIN console_users au ON au.user_id = p.assignee_user_id
LEFT JOIN LATERAL (SELECT left(e.body, 120) AS body, e.at FROM case_events e
                   WHERE e.case_id = p.case_id AND e.kind = 'note' ORDER BY e.event_id DESC LIMIT 1) n ON true
LEFT JOIN LATERAL (
  SELECT jsonb_agg(jsonb_build_array(y.agent_id, y.hostname) ORDER BY y.n) FILTER (WHERE y.n <= {MAX_HOSTS}) AS hosts,
         count(*) AS host_count
  FROM (SELECT x.agent_id, ha.hostname, row_number() OVER (ORDER BY ha.hostname, x.agent_id) AS n
        FROM (SELECT DISTINCT i.agent_id FROM case_items i
              WHERE i.case_id = p.case_id AND {item}) x
        LEFT JOIN agents ha ON ha.agent_id = x.agent_id) y) h ON true
ORDER BY p.ord",
        base = base(),
        counts = counts(),
        summary = summary(),
    )
}
