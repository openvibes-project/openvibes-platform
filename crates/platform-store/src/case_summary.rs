//! A case's page above the fold (roles plan 2026-10-25 step 5d, rulings
//! 2, 4, 10, 12, 13): the case with its visible counts, whether it is
//! ready to close, how long it has been open, each visible host with its
//! open problems, and who can see it. Nothing out of the viewer's
//! `cases.read` reach is counted or named; "ready" is close's own rule
//! over every item, and only that boolean is revealed.

use chrono::{DateTime, Utc};

use crate::{
    Client, StoreError,
    case_people::people,
    check_list_sql::{WINDOW, open_failing},
    console_cases::{
        CASE_COLUMNS, CASE_JOINS, CaseSummary, UserRef, blocking_item, case_counts, case_visible,
        is_uuid, item_in_scope, summary_from_row,
    },
    console_read::{AgentScope, agent_visibility},
    host_list::HostScopes,
};

/// A host's open problems; `None` where the viewer's permission for that
/// kind does not reach the host.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaseHostProblems {
    /// Open agent alarms (`alarms.read`).
    pub alarms: Option<i64>,
    /// Critical vulnerabilities as the Hosts list counts them
    /// (`vulnerabilities.read`).
    pub critical_vulns: Option<i64>,
    /// Open failing checks (`compliance.read`, `check_list_sql::open_failing`);
    /// also `None` when [`Self::compliance_stale`].
    pub failing_checks: Option<i64>,
    /// In compliance reach but no report in the last day (as the Hosts list
    /// and the host page say): the failing count is unknown, not 0.
    pub compliance_stale: bool,
}

/// A host of a visible item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseHost {
    /// Agent id.
    pub agent_id: String,
    /// Host name.
    pub hostname: Option<String>,
    /// OS id (`debian`).
    pub os_id: Option<String>,
    /// OS version.
    pub os_version: Option<String>,
    /// Display name (`Debian 12`).
    pub distribution: Option<String>,
    /// `linux` or `windows`.
    pub os_family: Option<String>,
    /// Its open problems.
    pub problems: CaseHostProblems,
}

/// Who can see the case (ruling 13): the first [`MAX_PEOPLE`] by name
/// and how many there are.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CasePeople {
    /// By display name.
    pub names: Vec<UserRef>,
    /// All of them the viewer may know of.
    pub total: i64,
    /// True exactly when the viewer's `cases.read` reaches every host, so
    /// `total` is everyone; otherwise it may leave out people who see the
    /// case only through hosts out of reach ("at least N"). It never depends
    /// on this case's hidden items, which it would otherwise reveal.
    pub complete: bool,
}

/// People a summary names.
pub const MAX_PEOPLE: i64 = 20;

/// The page's summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CasePageSummary {
    /// The case: `items` and `pending_items` count visible items only.
    pub case: CaseSummary,
    /// The closing note.
    pub resolution_note: Option<String>,
    /// Not closed, and no item (visible or hidden) blocks closing.
    pub ready: bool,
    /// Created to now, or to `closed_at`.
    pub open_for_seconds: i64,
    /// Hosts of visible items, by name.
    pub hosts: Vec<CaseHost>,
    /// Who can see it.
    pub people: CasePeople,
}

/// The `$1`/`$2` pair of a scope; no scope reaches nothing.
fn pair(scope: Option<&AgentScope>) -> (bool, Vec<String>) {
    scope.map_or((false, Vec::new()), |s| (s.is_global(), s.group_ids()))
}

/// Whether `user_id` in `scope` sees the case (as every case read decides).
pub async fn case_visible_to(
    client: &Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
) -> Result<bool, StoreError> {
    if !is_uuid(case_id) {
        return Ok(false);
    }
    let visible = case_visible("c");
    Ok(client
        .query_opt(
            &format!("SELECT 1 FROM cases c WHERE c.case_id = $4::text::uuid AND {visible}"),
            &[&scope.is_global(), &scope.group_ids(), &user_id, &case_id],
        )
        .await?
        .is_some())
}

/// The summary of `case_id` for `user_id`, whose `cases.read` reach is
/// `scopes.hosts`; the other scopes gate each problem kind. `None` when
/// the case is missing or invisible.
pub async fn case_summary(
    client: &Client,
    case_id: &str,
    scopes: &HostScopes<'_>,
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<CasePageSummary>, StoreError> {
    if !is_uuid(case_id) {
        return Ok(None);
    }
    let (global, groups) = pair(Some(scopes.hosts));
    let (counts, visible, blocking) = (case_counts(), case_visible("c"), blocking_item());
    let Some(row) = client
        .query_opt(
            &format!(
                "SELECT {CASE_COLUMNS}, {counts},
                    c.status <> 'closed' AND NOT EXISTS (SELECT 1 FROM case_items i
                        WHERE i.case_id = c.case_id AND {blocking}),
                    GREATEST(0, EXTRACT(EPOCH FROM COALESCE(c.closed_at, $5) - c.created_at))::bigint
                 FROM cases c {CASE_JOINS}
                 WHERE c.case_id = $4::text::uuid AND {visible}"
            ),
            &[&global, &groups, &user_id, &case_id, &now],
        )
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(CasePageSummary {
        case: summary_from_row(&row),
        resolution_note: row.get(17),
        ready: row.get(20),
        open_for_seconds: row.get(21),
        hosts: hosts(client, case_id, scopes, now).await?,
        people: people(client, scopes.hosts, case_id).await?,
    }))
}

async fn hosts(
    client: &Client,
    case_id: &str,
    scopes: &HostScopes<'_>,
    now: DateTime<Utc>,
) -> Result<Vec<CaseHost>, StoreError> {
    let (alarms, vulns, compliance) = (
        agent_visibility("a.agent_id", "$4", "$5"),
        agent_visibility("a.agent_id", "$6", "$7"),
        agent_visibility("a.agent_id", "$8", "$9"),
    );
    let (failing, in_scope) = (open_failing("$10"), item_in_scope("i"));
    // The Hosts list's rule (host_list_sql::base): in compliance reach with
    // no report in the last day, findings are not current and 0 would be wrong.
    let stale = format!("({compliance} AND COALESCE(s.seen < $10::timestamptz - {WINDOW}, true))");
    let (cases, a, v, f) = (
        pair(Some(scopes.hosts)),
        pair(scopes.alarms),
        pair(scopes.vulnerabilities),
        pair(scopes.compliance),
    );
    let rows = client
        .query(
            &format!(
                "SELECT a.agent_id, a.hostname, a.os_id, a.os_version,
                    console_distribution_name(a.distribution), a.os_family,
                    CASE WHEN {alarms} THEN (SELECT count(*) FROM alarms al WHERE al.agent_id = a.agent_id
                                               AND al.state = 'open' AND al.source = 'agent') END,
                    CASE WHEN {vulns} THEN COALESCE((SELECT v.critical FROM host_listed_critical v
                                                      WHERE v.agent_id = a.agent_id), 0)::bigint END,
                    CASE WHEN {compliance} AND NOT {stale} THEN (SELECT count(*) FROM current_findings f
                        LEFT JOIN console_finding_triage t USING (agent_id, rule_set_id, rule_id)
                        WHERE f.agent_id = a.agent_id AND {failing}) END,
                    {stale}
                 FROM agents a CROSS JOIN LATERAL (SELECT agent_seen_at(a.agent_id, a.last_seen_at) AS seen) s
                 WHERE a.agent_id IN (SELECT i.agent_id FROM case_items i
                                      WHERE i.case_id = $3::text::uuid AND {in_scope})
                 ORDER BY a.hostname, a.agent_id"
            ),
            &[
                &cases.0, &cases.1, &case_id, &a.0, &a.1, &v.0, &v.1, &f.0, &f.1, &now,
            ],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| CaseHost {
            agent_id: r.get(0),
            hostname: r.get(1),
            os_id: r.get(2),
            os_version: r.get(3),
            distribution: r.get(4),
            os_family: r.get(5),
            problems: CaseHostProblems {
                alarms: r.get(6),
                critical_vulns: r.get(7),
                failing_checks: r.get(8),
                compliance_stale: r.get(9),
            },
        })
        .collect())
}
