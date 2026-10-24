//! The SQL of a check's page (step 5c rulings 2, 11, 12, 14, 15): one
//! check's failing and inferred passing hosts in reach, under the
//! Compliance list's definitions (`check_list_sql`: failing, the pair
//! state and the shared [`passing_hosts_sql`]), so the page and its list
//! row agree. Only fixed internal strings are formatted in; every value is
//! bound.
//!
//! Parameters of [`base`]: `$1` global scope, `$2` scope group ids, `$3`
//! rule set, `$4` rule, `$5` now.

use crate::{
    check_list_sql::{PAIR_STATE, SEVERITIES, failing, passing_hosts_sql},
    console_read::agent_visibility,
};

/// CTEs `hosts` (the agents in reach), `k` (the check, when the list knows
/// it: a rule of its set's newest indexed version, or one with a current
/// finding on a host in reach; a check learnt only from hosts out of reach
/// is empty), `meta` (its newest indexed version), `f` (its current
/// findings in reach, with `failing`, the pair `state`, the assignee and
/// the triage version) and `pass` (its inferred passing hosts).
pub(crate) fn base() -> String {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let failing = failing("$5");
    let state = PAIR_STATE.replace("$12", "$5");
    let pass = passing_hosts_sql("hosts", "k", "$5::timestamptz");
    format!(
        "hosts AS MATERIALIZED (
  SELECT a.agent_id, a.hostname, host(a.last_address) AS address,
         console_distribution_name(a.distribution) AS os, a.health_at
  FROM agents a WHERE {visible}),
meta AS MATERIALIZED (
  SELECT m.* FROM console_rule_meta m WHERE m.rule_set_id = $3::text AND m.rule_id = $4::text
  ORDER BY m.rule_set_version DESC LIMIT 1),
k AS MATERIALIZED (
  SELECT $3::text AS rule_set_id, $4::text AS rule_id
  WHERE EXISTS (SELECT 1 FROM meta WHERE meta.rule_set_version =
                  (SELECT max(x.rule_set_version) FROM console_rule_meta x WHERE x.rule_set_id = $3::text))
     OR EXISTS (SELECT 1 FROM current_findings f JOIN hosts h ON h.agent_id = f.agent_id
                WHERE f.rule_set_id = $3::text AND f.rule_id = $4::text)),
f AS MATERIALIZED (
  SELECT f.agent_id, f.severity, f.rule_version, f.message, f.first_observed_at, f.last_observed_at,
         f.ended_at, f.detection, {failing} AS failing, {state} AS state, t.assigned_to,
         t.accepted_until, COALESCE(t.version, 0)::bigint AS triage_version
  FROM current_findings f JOIN k ON k.rule_set_id = f.rule_set_id AND k.rule_id = f.rule_id
  JOIN hosts h ON h.agent_id = f.agent_id
  LEFT JOIN console_finding_triage t
    ON t.agent_id = f.agent_id AND t.rule_set_id = f.rule_set_id AND t.rule_id = f.rule_id),
pass AS MATERIALIZED ({pass})"
    )
}

/// The page above the Hosts table as one JSON object (`$1`–`$5` as
/// [`base`]). `days` follows ruling 12 per UTC day ending today; a
/// finding neither failing nor ended (a legacy row or a P13 match no
/// longer seen) counts up to the day it was last seen.
pub(crate) fn summary() -> String {
    let failing_now = failing("$5");
    format!(
        "WITH {base},
day AS (SELECT d::date AS d FROM generate_series((($5::timestamptz AT TIME ZONE 'UTC')::date - 13)::timestamp,
                                                 ($5::timestamptz AT TIME ZONE 'UTC')::date::timestamp,
                                                 interval '1 day') d),
ev AS (
  SELECT (extract(epoch FROM h.changed_at) * 1000)::bigint AS at, h.event_id AS ord, 'triage' AS kind,
         COALESCE(u.display_name, h.changed_by) AS actor, h.agent_id, ho.hostname, h.from_state, h.to_state,
         h.note, NULL::bigint AS version
  FROM console_finding_triage_history h JOIN hosts ho ON ho.agent_id = h.agent_id
  LEFT JOIN console_users u ON u.user_id::text = h.changed_by
  WHERE h.rule_set_id = $3::text AND h.rule_id = $4::text AND EXISTS (SELECT 1 FROM k)
  UNION ALL
  SELECT (extract(epoch FROM f.first_observed_at) * 1000)::bigint, 0, 'failing', NULL, f.agent_id, h.hostname,
         NULL, NULL, NULL, NULL
  FROM f JOIN hosts h ON h.agent_id = f.agent_id
  UNION ALL
  SELECT (extract(epoch FROM f.ended_at) * 1000)::bigint, 0, 'passes_again', NULL, f.agent_id, h.hostname,
         NULL, NULL, NULL, NULL
  FROM f JOIN hosts h ON h.agent_id = f.agent_id WHERE f.ended_at IS NOT NULL
  UNION ALL
  SELECT (extract(epoch FROM b.published_at) * 1000)::bigint, 0, 'published', b.published_by, NULL, NULL,
         NULL, NULL, NULL, b.version
  FROM rule_bundles b WHERE b.rule_set_id = $3::text AND EXISTS (SELECT 1 FROM k))
SELECT jsonb_build_object(
  'failing', (SELECT count(*) FROM f WHERE failing),
  'open', (SELECT count(*) FROM f WHERE failing AND state = 'open'),
  'passing', (SELECT count(*) FROM pass),
  'failing_agents', (SELECT COALESCE(jsonb_agg(agent_id), '[]') FROM f WHERE failing),
  'agents', (SELECT COALESCE(jsonb_agg(agent_id), '[]') FROM (SELECT agent_id FROM f WHERE failing
                                                                UNION SELECT agent_id FROM pass) a),
  'people', (SELECT COALESCE(jsonb_agg(DISTINCT jsonb_build_array(u.user_id::text, u.display_name)), '[]')
             FROM f JOIN console_users u ON u.user_id = f.assigned_to WHERE f.failing AND f.state = 'open'),
  'first_seen', (SELECT jsonb_build_object('at', (extract(epoch FROM f.first_observed_at) * 1000)::bigint,
                                           'hostname', h.hostname)
                 FROM f JOIN hosts h ON h.agent_id = f.agent_id WHERE f.failing
                 ORDER BY f.first_observed_at, f.agent_id LIMIT 1),
  'severity', COALESCE((SELECT f.severity FROM f WHERE f.severity = ANY({SEVERITIES})
                        ORDER BY f.failing DESC, f.last_observed_at DESC, array_position({SEVERITIES}, f.severity)
                        LIMIT 1), (SELECT severity FROM meta)),
  'finding', (SELECT jsonb_build_object('message', f.message, 'rule_version', f.rule_version) FROM f
              ORDER BY f.last_observed_at DESC, f.agent_id LIMIT 1),
  'meta', (SELECT jsonb_build_object('title', m.title, 'message', m.message, 'explain', m.explain,
                                     'check', m.\"check\", 'rule_version', m.rule_version,
                                     'rule_set_version', m.rule_set_version, 'techniques', to_jsonb(m.techniques),
                                     'expression', m.expression) FROM meta m),
  'days', (SELECT jsonb_agg(n ORDER BY d) FROM (
             SELECT day.d, (SELECT count(*) FROM f
                            WHERE f.first_observed_at < (day.d + 1)::timestamp AT TIME ZONE 'UTC'
                              AND COALESCE(f.ended_at, CASE WHEN f.failing THEN 'infinity'::timestamptz END,
                                           f.last_observed_at) >= day.d::timestamp AT TIME ZONE 'UTC') AS n
             FROM day) x),
  'same_area', (SELECT jsonb_build_object('checks', count(DISTINCT (f.rule_set_id, f.rule_id)),
                                          'worst', ({SEVERITIES})[min(array_position({SEVERITIES}, f.severity))])
                FROM current_findings f JOIN hosts h ON h.agent_id = f.agent_id
                WHERE {failing_now} AND console_check_area(f.rule_id) = console_check_area($4::text)
                  AND (f.rule_set_id, f.rule_id) <> ($3::text, $4::text) AND EXISTS (SELECT 1 FROM k)),
  'history', (SELECT COALESCE(jsonb_agg(to_jsonb(e) - 'ord' ORDER BY e.at DESC, e.ord DESC), '[]') FROM (
                SELECT * FROM ev ORDER BY at DESC, ord DESC LIMIT 50) e))",
        base = base(),
    )
}

/// The Hosts table (`$1`–`$5` as [`base`], `$6` segment, `$7` limit, `$8`
/// offset): failing pairs in any triage state and passing hosts, the
/// segment counts as JSON on every row, then the page by host name and
/// agent id; an empty page is one row with the counts only.
pub(crate) fn hosts() -> String {
    format!(
        "WITH {base},
pairs AS (
  SELECT f.agent_id, f.state, f.detection -> 'inputs' AS inputs, f.assigned_to, f.last_observed_at AS checked_at,
         f.triage_version, f.accepted_until FROM f WHERE f.failing
  UNION ALL
  SELECT p.agent_id, 'passing', NULL, NULL, p.health_at, NULL, NULL FROM pass p),
counts AS (SELECT jsonb_build_object('all', count(*), 'failing', count(*) FILTER (WHERE state <> 'passing'),
                                     'passing', count(*) FILTER (WHERE state = 'passing')) AS c FROM pairs),
page AS (
  SELECT p.*, h.hostname, h.os, h.address, row_number() OVER (ORDER BY h.hostname NULLS LAST, p.agent_id) AS ord
  FROM pairs p JOIN hosts h ON h.agent_id = p.agent_id
  WHERE $6::text = 'all' OR ($6::text = 'passing') = (p.state = 'passing')
  ORDER BY ord LIMIT $7 OFFSET $8)
SELECT c.c, p.agent_id, p.hostname, p.os, p.address, p.state, p.inputs, p.assigned_to::text, u.display_name,
       p.checked_at, p.triage_version, p.accepted_until
FROM counts c LEFT JOIN page p ON true
LEFT JOIN console_users u ON u.user_id = p.assigned_to
ORDER BY p.ord",
        base = base()
    )
}

/// Hosts in reach (`$1`, `$2`) listening on exposed `$3` protocol and
/// `$4` port.
pub(crate) fn port_hosts() -> String {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    format!(
        "SELECT count(DISTINCT l.agent_id) FROM host_listeners l JOIN agents a ON a.agent_id = l.agent_id
         WHERE {visible} AND l.protocol = $3::text AND l.port = $4::int AND l.exposed"
    )
}

/// Hosts in reach (`$1`, `$2`) running unit `$3`.
pub(crate) fn unit_hosts() -> String {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    format!(
        "SELECT count(*) FROM host_services s JOIN agents a ON a.agent_id = s.agent_id
         WHERE {visible} AND s.unit = $3::text"
    )
}
