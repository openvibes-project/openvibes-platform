//! The SQL of the Compliance list's one statement (step 5c rulings 2–7).
//! Hosts in reach are numbered into classes (alike for every count), current
//! findings counted per check and class into `fcube` (failing pairs, by
//! pair state and assignee) and `fall` (severities and times), inferred
//! passing hosts per check and class into `pcube`; `r` folds them into one
//! row per check and group-filter side, and every filter, count and the
//! page read `r`. Only fixed internal strings are formatted in; every value
//! is bound.
//!
//! Parameters: `$1` global scope, `$2` scope group ids, `$3` search, `$4`
//! state (NULL for all), `$5` severity, `$6` rule set, `$7` area, `$8`
//! group, `$9` host, `$10` assignee user id (text), `$11` unassigned,
//! `$12` now, `$13` limit, `$14` offset.

use crate::{check_area::collectors_ok_sql, check_list::CheckSort, vuln_list_sql::HOSTS_BODY};

/// How far back a finding still counts as failing: the window the
/// Compliance groups use by default (`compliance/groups.rs`, 24 hours).
pub(crate) const WINDOW: &str = "interval '24 hours'";

/// Severities, most severe first; `r.sev` is a position in it.
pub(crate) const SEVERITIES: &str = "ARRAY['critical','high','medium','low','info']";

/// A current finding `f` fails at `now` (an SQL timestamptz expression):
/// open (ruling 2) and seen within the window.
pub(crate) fn failing(now: &str) -> String {
    format!("(f.ended_at IS NULL AND f.last_observed_at >= ({now})::timestamptz - {WINDOW})")
}

/// A current finding `f`, with its triage `t`, is an open failing pair at
/// `now` (an SQL timestamptz expression): failing, and open by
/// [`PAIR_STATE`] (an expired acceptance is open). The host page's tile and
/// the Hosts list count these, so they agree with the Compliance list.
pub(crate) fn open_failing(now: &str) -> String {
    let state = PAIR_STATE.replace("$12::timestamptz", &format!("({now})::timestamptz"));
    format!("({} AND {state} = 'open')", failing(now))
}

/// A current finding `f` keeps its host from passing: failing, or an open
/// P13 match (`source = 'changes'`) however old. Open changes rows are
/// refreshed hourly while the agent's digest matches; a host stuck in a
/// resync keeps fresh health while its open matches age, and is neither
/// failing nor passing. Legacy `scan` rows never end, so only their age
/// counts.
fn blocks(now: &str) -> String {
    format!(
        "(f.ended_at IS NULL AND (f.source = 'changes' OR f.last_observed_at >= ({now})::timestamptz - {WINDOW}))"
    )
}

/// User decision 1, per host `a` (an `agents` row) at `now` (an SQL
/// timestamptz expression): the rule sets it runs, as a jsonb object of
/// set id → accepted version (NULL unless it is active with heartbeat
/// health at most 24 hours old): those its health lists with a version
/// (the agent reports none for a set it never accepted), not
/// `not_assigned` and not refused. A version is kept only as 1–18 digits,
/// so the `::bigint` casts on it never fail the statement; any other value
/// (above `i64::MAX`, fractional, a string) is not running.
fn healthy_sets(now: &str) -> String {
    format!(
        "CASE WHEN a.status = 'active' AND a.health_at >= ({now})::timestamptz - interval '24 hours' THEN (
         SELECT COALESCE(jsonb_object_agg(e ->> 'id', e -> 'version'), '{{}}')
         FROM jsonb_array_elements(CASE WHEN jsonb_typeof(a.health -> 'rule_sets') = 'array'
                                        THEN a.health -> 'rule_sets' ELSE '[]'::jsonb END) e
         WHERE jsonb_typeof(e -> 'version') = 'number' AND (e ->> 'version') ~ '^[0-9]{{1,18}}$'
           AND (e ->> 'state') IS DISTINCT FROM 'not_assigned'
           AND COALESCE(e ->> 'refused', 'false') = 'false') END"
    )
}

/// The collectors `a`'s last scan reports `ok`, as a jsonb array of names.
const OK_COLLECTORS: &str = "jsonb_path_query_array(a.health,
       '$.last_scan.collectors.keyvalue() ? (@.value == \"ok\").key', '{}', true)";

/// `a`'s last scan reported at least one collector, every one `ok`.
const ALL_OK: &str = "(jsonb_typeof(a.health -> 'last_scan' -> 'collectors') = 'object'
       AND a.health -> 'last_scan' -> 'collectors' <> '{}'::jsonb
       AND NOT jsonb_path_exists(a.health, '$.last_scan.collectors.* ? (@ != \"ok\")', '{}', true))";

/// A host with `sets`, `colls` and `all_ok` (from [`healthy_sets`],
/// [`OK_COLLECTORS`] and [`ALL_OK`]) runs the check (`set`, `rule`): it runs
/// the set at a version whose indexed bundle has the rule (any version
/// when no indexed bundle of the set has it), and the rule's collectors
/// (`check_area::check_collectors`) ran ok.
fn runs(sets: &str, colls: &str, all_ok: &str, set: &str, rule: &str) -> String {
    let collectors = collectors_ok_sql(rule, colls, all_ok);
    format!(
        "(({sets}) ? {set} AND {collectors}
   AND (EXISTS (SELECT 1 FROM console_rule_meta m WHERE m.rule_set_id = {set} AND m.rule_id = {rule}
                  AND m.rule_set_version = (({sets}) ->> {set})::bigint)
        OR NOT EXISTS (SELECT 1 FROM console_rule_meta m WHERE m.rule_set_id = {set} AND m.rule_id = {rule})))"
    )
}

/// User decision 1, shared with a check's page: the hosts of `hosts` (a
/// relation with `agent_id`, already the hosts in reach) that pass the
/// checks of `checks` (a relation with `rule_set_id`, `rule_id`) at `now`
/// (an SQL timestamptz expression), as `hosts`' columns plus
/// `rule_set_id` and `rule_id`. A host passes when it is active, its
/// heartbeat health is at most 24 hours old and lists the rule set with a
/// version, neither `not_assigned` nor refused, that version's indexed
/// bundle has the rule (any version when none has it), the rule's
/// collectors ran `ok` in its last scan (every reported collector for a
/// rule ID with no known prefix), and no finding [`blocks`] it. The list
/// counts the same rule per host class instead (`classes`, `pcube`).
pub fn passing_hosts_sql(hosts: &str, checks: &str, now: &str) -> String {
    let runs = runs(
        &healthy_sets(now),
        OK_COLLECTORS,
        ALL_OK,
        "k.rule_set_id",
        "k.rule_id",
    );
    let blocks = blocks(now);
    // An EXCEPT, not NOT EXISTS: the planner merged that anti-join on the
    // check alone and filtered hosts per pair (minutes at 500,000 findings).
    format!(
        "SELECT hh.*, x.rule_set_id, x.rule_id
  FROM (SELECT a.agent_id, k.rule_set_id, k.rule_id
        FROM {hosts} h0 JOIN agents a ON a.agent_id = h0.agent_id CROSS JOIN {checks} k
        WHERE {runs}
        EXCEPT
        SELECT f.agent_id, f.rule_set_id, f.rule_id FROM current_findings f
        WHERE {blocks} AND (f.rule_set_id, f.rule_id) IN (SELECT rule_set_id, rule_id FROM {checks})) x
  JOIN {hosts} hh ON hh.agent_id = x.agent_id"
    )
}

/// The Vulnerabilities list's hosts in reach (`vuln_list_sql::HOSTS`) with
/// each host's [`healthy_sets`], [`OK_COLLECTORS`] and [`ALL_OK`] (`sets`,
/// `colls`, `all_ok`), worked out once per agent in its grouped subquery.
fn hosts_in_reach() -> String {
    format!(
        "(SELECT a.agent_id, {} AS sets, {OK_COLLECTORS} AS colls, {ALL_OK} AS all_ok,{HOSTS_BODY}",
        healthy_sets("$12")
    )
}

/// One filter whose own condition the counts of its values leave out. The
/// host filter narrows the hosts themselves; the group filter picks the
/// `grp` side of `r`.
#[derive(Clone, Copy, PartialEq)]
enum Facet {
    State,
    Assignee,
    Severity,
    RuleSet,
    Area,
}

const FACETS: [Facet; 3] = [Facet::Severity, Facet::RuleSet, Facet::Area];

/// The `r` rows the page shows: the chosen group side.
const MAIN: &str = "r.grp = ($8::text IS NOT NULL)";

fn filter(facet: Facet) -> &'static str {
    match facet {
        Facet::Severity => {
            "($5::text IS NULL OR r.sev = array_position(ARRAY['critical','high','medium','low','info'], $5))"
        }
        Facet::RuleSet => "($6::text IS NULL OR r.rule_set_id = $6)",
        Facet::Area => "($7::text IS NULL OR r.area = $7)",
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
    let search = "($3::text IS NULL OR strpos(lower(r.title), lower($3)) > 0
      OR strpos(lower(r.rule_id), lower($3)) > 0 OR strpos(lower(r.rule_set_id), lower($3)) > 0)";
    FACETS
        .iter()
        .filter(|f| !skip.contains(f))
        .map(|f| filter(*f))
        .chain([pair, search])
        .collect::<Vec<_>>()
        .join(" AND ")
}

/// A pair (a `cube` row with a state: failing or passing) in the chosen
/// state; NULL `$4` is every state.
const STATE_OK: &str = "(c.state IS NOT NULL AND ($4::text IS NULL OR c.state = $4))";
/// A pair matching the Assignee filter; a passing pair has no assignee and
/// matches only no filter.
const ASSIGNEE_OK: &str = "(c.state IS NOT NULL AND (($10::text IS NULL AND NOT $11::boolean)
  OR (c.state <> 'passing' AND (($11 AND c.assignee IS NULL) OR c.assignee = $10::text::uuid))))";

/// A failing finding's triage state (no row is open, an accepted risk
/// expired by `$12` is open), over `t`.
pub(crate) const PAIR_STATE: &str =
    "COALESCE(CASE WHEN t.state = 'accepted_risk' AND t.accepted_until <= $12::timestamptz
                THEN 'open' ELSE t.state END, 'open')";

/// `glist`; `hosts` ([`hosts_in_reach`], with `cls`: hosts alike for
/// every count share it: group side, mask, set versions and collectors);
/// `classes` (one row per `cls`, with its hosts); `titles` (each rule's
/// newest indexed title and severity); `fall` (current findings in reach per check,
/// severity and class: failing ones, their first seen, the last seen of
/// failing and of all, and those that [`blocks`] passing; no triage join,
/// most findings have no triage row); `ftri` (triaged failing pairs per pair state, assignee and class);
/// `fcube` (failing pairs per check, pair state, assignee and class:
/// `fall` as open and unassigned, `ftri` moved to its state); `checks`
/// (the rules of each set's newest indexed version and every check with
/// a current finding on a host in reach, so a site rule found only out of
/// reach is never named; a check without metadata leaves the list once no
/// host in reach has a finding for it, even when hosts in reach still
/// pass it); `pcube` (passing hosts per check and class: the class's hosts
/// when they run the check, less those a finding [`blocks`]). Grouping by a class
/// number, not the mask, lets the 500,000-finding aggregate hash (a
/// varbit key sorted them on disk), and counts passing hosts exactly per
/// group.
fn cubes() -> String {
    let failing = failing("$12");
    let hosts = hosts_in_reach();
    let blocks = blocks("$12");
    let runs = runs(
        "c.sets",
        "c.colls",
        "c.all_ok",
        "k.rule_set_id",
        "k.rule_id",
    );
    format!(
        "glist AS MATERIALIZED (
  SELECT COALESCE(array_agg(DISTINCT asset_group_id::text), '{{}}') AS ids FROM console_host_group_membership),
hosts AS MATERIALIZED (
  SELECT h.*, dense_rank() OVER (ORDER BY h.in_group, h.mask::text, h.sets, h.colls, h.all_ok) AS cls FROM {hosts} h),
classes AS MATERIALIZED (
  SELECT DISTINCT ON (cls) cls, in_group, mask, sets, colls, all_ok, count(*) OVER (PARTITION BY cls) AS n
  FROM hosts ORDER BY cls),
titles AS MATERIALIZED (
  SELECT DISTINCT ON (rule_set_id, rule_id) rule_set_id, rule_id, title, severity FROM console_rule_meta
  ORDER BY rule_set_id, rule_id, rule_set_version DESC),
fall AS MATERIALIZED (
  SELECT f.rule_set_id, f.rule_id, f.severity, h.cls, count(*) FILTER (WHERE {failing}) AS n,
         min(f.first_observed_at) FILTER (WHERE {failing}) AS since,
         max(f.last_observed_at) FILTER (WHERE {failing}) AS seen_failing, max(f.last_observed_at) AS seen,
         count(*) FILTER (WHERE {blocks}) AS blocked
  FROM current_findings f JOIN hosts h ON h.agent_id = f.agent_id
  GROUP BY 1, 2, 3, 4),
ftri AS MATERIALIZED (
  SELECT f.rule_set_id, f.rule_id, {PAIR_STATE} AS state, t.assigned_to AS assignee, h.cls, count(*) AS n
  FROM console_finding_triage t
  JOIN current_findings f ON f.agent_id = t.agent_id AND f.rule_set_id = t.rule_set_id AND f.rule_id = t.rule_id
  JOIN hosts h ON h.agent_id = f.agent_id
  WHERE {failing}
  GROUP BY 1, 2, 3, 4, 5),
fcube AS MATERIALIZED (
  SELECT x.*, c.in_group, c.mask
  FROM (SELECT rule_set_id, rule_id, state, assignee, cls, sum(n)::bigint AS n
        FROM (SELECT rule_set_id, rule_id, 'open' AS state, NULL::uuid AS assignee, cls, n FROM fall WHERE n > 0
              UNION ALL
              SELECT rule_set_id, rule_id, state, assignee, cls, n FROM ftri
              UNION ALL
              SELECT rule_set_id, rule_id, 'open', NULL, cls, -n FROM ftri) y
        GROUP BY 1, 2, 3, 4, 5 HAVING sum(n) > 0) x
  JOIN classes c ON c.cls = x.cls),
checks AS MATERIALIZED (
  SELECT m.rule_set_id, m.rule_id FROM console_rule_meta m
  WHERE m.rule_set_version = (SELECT max(x.rule_set_version) FROM console_rule_meta x WHERE x.rule_set_id = m.rule_set_id)
  UNION
  SELECT DISTINCT rule_set_id, rule_id FROM fall),
pcube AS MATERIALIZED (
  SELECT k.rule_set_id, k.rule_id, c.in_group, c.mask, c.n - COALESCE(x.n, 0) AS n
  FROM checks k CROSS JOIN classes c
  LEFT JOIN (SELECT rule_set_id, rule_id, cls, sum(blocked) AS n FROM fall GROUP BY 1, 2, 3) x
    ON x.rule_set_id = k.rule_set_id AND x.rule_id = k.rule_id AND x.cls = c.cls
  WHERE COALESCE({runs}, false) AND c.n > COALESCE(x.n, 0))"
    )
}

/// `keyed`: every cube row once on the all-groups side (`grp` false) and,
/// with a group filter, once more on the group's side; `kpers`: per check,
/// side and assignee, whether a failing pair in the chosen state has them
/// and whether an open one does; `r`: one row per check and side that has
/// a pair.
fn rows() -> String {
    let count = |cond: &str| format!("COALESCE(sum(c.n) FILTER (WHERE {cond}), 0)::bigint");
    let [failing, passing, open, mitigated, accepted, fp] = [
        "c.state <> 'passing'",
        "c.state = 'passing'",
        "c.state = 'open'",
        "c.state = 'mitigated'",
        "c.state = 'accepted_risk'",
        "c.state = 'false_positive'",
    ]
    .map(count);
    let st = |s: &str| format!("bool_or(c.state = '{s}' AND {ASSIGNEE_OK}) AS st_{s}");
    let flags = [
        "open",
        "mitigated",
        "accepted_risk",
        "false_positive",
        "passing",
    ]
    .map(st)
    .join(", ");
    format!(
        "keyed AS MATERIALIZED (
  SELECT gs.grp, c.* FROM (
    SELECT rule_set_id, rule_id, state, assignee, in_group, n, mask, NULL AS severity,
           NULL::timestamptz AS since, NULL::timestamptz AS seen_failing, NULL::timestamptz AS seen FROM fcube
    UNION ALL
    SELECT rule_set_id, rule_id, 'passing', NULL, in_group, n, mask, NULL, NULL, NULL, NULL FROM pcube
    UNION ALL
    SELECT f.rule_set_id, f.rule_id, NULL, NULL, c.in_group, 0, c.mask, f.severity, f.since, f.seen_failing, f.seen
    FROM fall f JOIN classes c ON c.cls = f.cls) c
  CROSS JOIN LATERAL (SELECT false AS grp UNION ALL SELECT true WHERE $8::text IS NOT NULL AND c.in_group) gs),
kpers AS MATERIALIZED (
  SELECT c.rule_set_id, c.rule_id, c.grp, c.assignee, bool_or({STATE_OK}) AS s_ok, bool_or(c.state = 'open') AS open
  FROM keyed c WHERE c.assignee IS NOT NULL AND c.state IS NOT NULL GROUP BY 1, 2, 3, 4),
r AS MATERIALIZED (
  SELECT k.*, COALESCE(o.people, 0) AS people, o.person, COALESCE(m.title, k.rule_id) AS title,
         COALESCE(k.sev0, array_position({SEVERITIES}, m.severity)) AS sev, console_check_area(k.rule_id) AS area
  FROM (SELECT c.rule_set_id, c.rule_id, c.grp, {failing} AS failing, {passing} AS passing,
               {open} AS open, {mitigated} AS mitigated, {accepted} AS accepted_risk, {fp} AS false_positive,
               min(c.since) AS since,
               array_position({SEVERITIES}, (array_agg(c.severity ORDER BY c.seen_failing IS NULL,
                   COALESCE(c.seen_failing, c.seen) DESC,
                   array_position({SEVERITIES}, c.severity)) FILTER (WHERE c.severity IS NOT NULL))[1]) AS sev0,
               bool_or({STATE_OK} AND {ASSIGNEE_OK}) AS m_sa, bool_or({ASSIGNEE_OK}) AS m_a, bool_or({STATE_OK}) AS m_s,
               {flags},
               COALESCE(bool_or(c.assignee IS NULL AND c.state <> 'passing' AND {STATE_OK}), false) AS un,
               bit_or(c.mask) FILTER (WHERE {STATE_OK} AND {ASSIGNEE_OK}) AS mask
        FROM keyed c GROUP BY 1, 2, 3 HAVING bool_or(c.state IS NOT NULL)) k
  LEFT JOIN titles m ON m.rule_set_id = k.rule_set_id AND m.rule_id = k.rule_id
  LEFT JOIN (SELECT kp.rule_set_id, kp.rule_id, kp.grp, count(*) AS people, min(kp.assignee::text) AS person
             FROM kpers kp WHERE kp.open GROUP BY 1, 2, 3) o
    ON o.rule_set_id = k.rule_set_id AND o.rule_id = k.rule_id AND o.grp = k.grp)"
    )
}

/// CTE `counts`: one JSON object of every facet's values, each with the
/// other filters applied. Rule set, area, group and person values come
/// from `r`, which holds only pairs in reach; the chosen group is added
/// with 0 when the scope reaches it.
fn counts() -> String {
    let state = except(&[Facet::State]);
    let severity = except(&[Facet::Severity]);
    let rule_set = except(&[Facet::RuleSet]);
    let area = except(&[Facet::Area]);
    let group = except(&[Facet::State, Facet::Assignee]);
    let assignee = except(&[Facet::Assignee]);
    format!(
        "counts AS (
  SELECT jsonb_build_object(
    'state', (SELECT jsonb_build_object('open', count(*) FILTER (WHERE r.st_open),
                'mitigated', count(*) FILTER (WHERE r.st_mitigated),
                'accepted_risk', count(*) FILTER (WHERE r.st_accepted_risk),
                'false_positive', count(*) FILTER (WHERE r.st_false_positive),
                'passing', count(*) FILTER (WHERE r.st_passing), 'all', count(*) FILTER (WHERE r.m_a))
              FROM r WHERE {MAIN} AND {state}),
    'severity', (SELECT COALESCE(jsonb_object_agg(({SEVERITIES})[r.sev], r.n), '{{}}')
                 FROM (SELECT r.sev, count(*) AS n FROM r WHERE {MAIN} AND r.sev IS NOT NULL AND {severity}
                       GROUP BY r.sev) r),
    'rule_sets', (SELECT COALESCE(jsonb_agg(jsonb_build_array(s.rule_set_id, s.n) ORDER BY s.rule_set_id), '[]')
                  FROM (SELECT r.rule_set_id, count(*) FILTER (WHERE {rule_set}) AS n FROM r WHERE {MAIN}
                        GROUP BY 1) s),
    'areas', (SELECT COALESCE(jsonb_agg(jsonb_build_array(s.area, s.n) ORDER BY s.area), '[]')
              FROM (SELECT r.area, count(*) FILTER (WHERE {area}) AS n FROM r WHERE {MAIN} GROUP BY 1) s),
    'groups', (SELECT COALESCE(jsonb_agg(jsonb_build_array(g.asset_group_id::text, g.name, g.kind, COALESCE(c.n, 0))), '[]')
               FROM console_asset_groups g LEFT JOIN (
                 SELECT gl.gid, count(*) AS n
                 FROM glist, unnest(glist.ids) WITH ORDINALITY gl(gid, ord) JOIN r ON get_bit(r.mask, gl.ord::int - 1) = 1
                 WHERE NOT r.grp AND {group}
                 GROUP BY gl.gid) c ON c.gid = g.asset_group_id::text
               WHERE c.n > 0
                  OR (g.asset_group_id::text = lower($8) AND ($1::boolean OR g.asset_group_id::text = ANY($2::text[])))),
    'unassigned', (SELECT count(*) FROM r WHERE {MAIN} AND {assignee} AND r.un),
    'people', (SELECT COALESCE(jsonb_agg(jsonb_build_array(u.user_id::text, u.display_name, c.n)), '[]')
               FROM (SELECT kp.assignee, count(*) AS n FROM r JOIN kpers kp
                       ON kp.rule_set_id = r.rule_set_id AND kp.rule_id = r.rule_id AND kp.grp = r.grp AND kp.s_ok
                     WHERE {MAIN} AND {assignee} GROUP BY kp.assignee) c
               JOIN console_users u ON u.user_id = c.assignee)) AS counts)"
    )
}

/// CTE `summary`: over the rows matching every filter but the state's,
/// those with an open failing pair (matching the Assignee filter): how
/// many, on how many hosts (per host, its first open failing pair through
/// the primary key; with a person chosen, from their triage rows), how many are critical or have no open pair
/// assigned, and how many per rule set.
fn summary() -> String {
    let rows = format!("{MAIN} AND {} AND r.st_open", except(&[Facet::State]));
    let assignee = ASSIGNEE_OK
        .replace("c.state IS NOT NULL", "true")
        .replace("c.state <> 'passing'", "true")
        .replace("c.assignee", "t.assigned_to");
    let failing = failing("$12");
    format!(
        "srows AS MATERIALIZED (SELECT r.* FROM r WHERE {rows}),
summary AS (
  SELECT jsonb_build_object(
    'failing_checks', (SELECT count(*) FROM srows),
    'critical', (SELECT count(*) FROM srows WHERE sev = 1),
    'unassigned', (SELECT count(*) FROM srows WHERE people = 0),
    'rule_sets', (SELECT COALESCE(jsonb_agg(jsonb_build_array(s.rule_set_id, s.n) ORDER BY s.rule_set_id), '[]')
                  FROM (SELECT rule_set_id, count(*) AS n FROM srows GROUP BY 1) s),
    'hosts', CASE WHEN $10::text IS NOT NULL THEN (
               SELECT count(DISTINCT t.agent_id) FROM console_finding_triage t
               JOIN current_findings f ON f.agent_id = t.agent_id AND f.rule_set_id = t.rule_set_id AND f.rule_id = t.rule_id
               JOIN hosts h ON h.agent_id = f.agent_id AND h.in_group
               WHERE t.assigned_to = $10::text::uuid AND {failing} AND {PAIR_STATE} = 'open'
                 AND (f.rule_set_id, f.rule_id) IN (SELECT rule_set_id, rule_id FROM srows))
             ELSE (
               SELECT count(*) FROM hosts h CROSS JOIN LATERAL (
                 SELECT 1 FROM current_findings f
                 LEFT JOIN console_finding_triage t
                   ON t.agent_id = f.agent_id AND t.rule_set_id = f.rule_set_id AND t.rule_id = f.rule_id
                 WHERE f.agent_id = h.agent_id AND {failing} AND {PAIR_STATE} = 'open' AND {assignee}
                   AND f.rule_set_id || ' ' || f.rule_id = ANY(ARRAY(SELECT rule_set_id || ' ' || rule_id FROM srows))
                 LIMIT 1) x
               WHERE h.in_group) END) AS summary)"
    )
}

/// The sort keys over a `p` row, nulls last, ending in the key tie-break.
fn order(sort: CheckSort, descending: bool) -> String {
    let dir = if descending { "DESC" } else { "ASC" };
    let keys: &[&str] = match sort {
        CheckSort::Severity => &["6 - p.sev", "p.failing"],
        CheckSort::Failing => &["p.failing"],
        CheckSort::Since => &["p.since"],
        CheckSort::Title => &["lower(p.title)"],
    };
    keys.iter()
        .map(|k| format!("{k} {dir} NULLS LAST"))
        .chain([format!("p.rule_set_id {dir}, p.rule_id {dir}")])
        .collect::<Vec<_>>()
        .join(", ")
}

/// The statement: the meta (total, counts, summary) as JSON on the first
/// row only, then the page (`$13` limit, `$14` offset) with each row's
/// assignee. An empty page still returns one row, with the meta and no key.
pub(crate) fn statement(sort: CheckSort, descending: bool) -> String {
    let all = except(&[]);
    let order = order(sort, descending);
    format!(
        "WITH {cubes}, {rows}, {counts}, {summary},
meta AS (
  SELECT jsonb_build_object('total', (SELECT count(*) FROM r WHERE {MAIN} AND {all}),
                            'counts', (SELECT counts FROM counts),
                            'summary', (SELECT summary FROM summary)) AS meta),
page AS (
  SELECT p.*, row_number() OVER (ORDER BY {order}) AS ord
  FROM (SELECT * FROM r WHERE {MAIN} AND {all}) p ORDER BY {order} LIMIT $13 OFFSET $14)
SELECT CASE WHEN p.ord IS NOT DISTINCT FROM (SELECT min(ord) FROM page) THEN m.meta END,
       p.rule_set_id, p.rule_id, p.title, ({SEVERITIES})[p.sev], p.area, p.failing, p.passing,
       p.open, p.mitigated, p.accepted_risk, p.false_positive, p.since, u.display_name, p.people, p.person
FROM meta m LEFT JOIN page p ON true
LEFT JOIN console_users u ON u.user_id::text = p.person
ORDER BY p.ord",
        cubes = cubes(),
        rows = rows(),
        counts = counts(),
        summary = summary(),
    )
}
