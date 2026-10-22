//! An alarm's page above the fold (roles spec §10.3; plan user decisions 1
//! and 2, rulings 8 and 9): the alarm as a list row with its detail, the
//! rule's text, its commands seen (siblings), the last 24 hours and the
//! Related card. An alarm outside the `alarms.read` scope reads as absent.

use chrono::{DateTime, Utc};

use crate::{
    Client, StoreError,
    alarm_list::{AlarmListRow, AlarmSeverity, AlarmState},
    console_alarms::{AlarmTriage, detail},
    console_read::{AgentScope, agent_visibility},
    host_summary::{Top, TopAlarm, top_alarms, top_vulnerabilities},
    rule_meta,
    vulns::VulnRow,
};

/// Other open alarms on the host shown in the Related card.
const HOST_ALARMS: i64 = 5;

/// What the "What happened" card says.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleText {
    /// The rule's title; the alarm's message when the rule is not indexed.
    pub title: String,
    /// The rule's message; the alarm's when not indexed.
    pub message: String,
    /// What a match means.
    pub explain: Option<String>,
    /// What a person should look at.
    pub check: Option<String>,
    /// ATT&CK technique ids (empty when not indexed).
    pub techniques: Vec<String>,
}

/// One command seen: a sibling alarm (same host, rule set, rule, program and
/// parent), one distinct command line.
#[derive(Clone, Debug)]
pub struct Command {
    /// The platform's alarm id.
    pub id: i64,
    /// Its host.
    pub agent_id: String,
    /// The command line, masked as stored.
    pub args: Vec<String>,
    /// Starts matched.
    pub count: i64,
    /// First start that matched.
    pub first_seen: DateTime<Utc>,
    /// Last start that matched.
    pub last_seen: DateTime<Utc>,
    /// Triage state.
    pub state: String,
    /// The suppression that closed it.
    pub suppressed_by: Option<i64>,
    /// The open case holding it: (case id, number).
    pub case: Option<(String, i64)>,
}

/// Other hosts in reach with an open, unsuppressed alarm from this rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Elsewhere {
    /// Hosts.
    pub hosts: i64,
    /// Their open alarms from the rule.
    pub open: i64,
}

/// Everything above the fold on one alarm's page.
#[derive(Clone, Debug)]
pub struct AlarmPageSummary {
    /// The list-row fields.
    pub alarm: AlarmListRow,
    /// Rule set version.
    pub rule_set_version: i64,
    /// Rule version.
    pub rule_version: i64,
    /// 0 to 100.
    pub confidence: i16,
    /// The process (masked args) as the agent sent it.
    pub process: serde_json::Value,
    /// Its ancestors, nearest first.
    pub ancestors: serde_json::Value,
    /// When ingest stored it.
    pub received_at: DateTime<Utc>,
    /// Current triage.
    pub triage: AlarmTriage,
    /// The rule's text.
    pub rule: RuleText,
    /// The alarm and its siblings, most starts first, then by id.
    pub commands: Vec<Command>,
    /// Starts of the alarm and its siblings per hour, the 24 hours ending
    /// with the current one, oldest first.
    pub hourly: Vec<i64>,
    /// The host's other open agent alarms.
    pub host_alarms: Top<TopAlarm>,
    /// The host's open advisories (the host page's rules), with
    /// `vulnerabilities.read` on the host.
    pub host_vulnerabilities: Option<Top<VulnRow>>,
    /// Same rule elsewhere.
    pub elsewhere: Elsewhere,
    /// The groups holding the host.
    pub host_groups: Vec<String>,
    /// The host is imported (reached only globally).
    pub imported: bool,
}

impl AlarmPageSummary {
    /// Whether `scope` reaches the alarm's host: `agent_visibility`'s rule.
    #[must_use]
    pub fn reaches(&self, scope: &AgentScope) -> bool {
        match scope {
            AgentScope::Global => true,
            AgentScope::AssetGroups(ids) => {
                !self.imported && self.host_groups.iter().any(|g| ids.contains(g))
            }
        }
    }
}

/// The page of alarm `id`, or `None` when it is missing or `alarms` does not
/// reach its host. `vulnerabilities` is the viewer's `vulnerabilities.read`
/// scope, if any.
pub async fn alarm_summary(
    client: &Client,
    id: i64,
    alarms: &AgentScope,
    vulnerabilities: Option<&AgentScope>,
    now: DateTime<Utc>,
) -> Result<Option<AlarmPageSummary>, StoreError> {
    let Some(d) = detail(client, alarms, id).await? else {
        return Ok(None);
    };
    let a = d.summary;
    let x = client
        .query_one(
            "SELECT a.os_family, console_distribution_name(a.distribution), a.status = 'imported',
                    COALESCE(rm.techniques, '{}'), al.assigned_to::text, u.display_name,
                    cs.case_id::text, cs.number,
                    ARRAY(SELECT g.asset_group_id::text FROM console_asset_groups g
                          WHERE console_host_in_group(a.agent_id, g.asset_group_id))
             FROM alarms al JOIN agents a ON a.agent_id = al.agent_id
             LEFT JOIN console_rule_meta rm
               ON rm.rule_set_id = al.rule_set_id AND rm.rule_set_version = al.rule_set_version
              AND rm.rule_id = al.rule_id AND rm.rule_version = al.rule_version
             LEFT JOIN console_users u ON u.user_id = al.assigned_to
             LEFT JOIN case_items ci ON ci.kind = 'alarm' AND ci.active AND ci.ref = al.id::text
             LEFT JOIN cases cs ON cs.case_id = ci.case_id
             WHERE al.id = $1",
            &[&id],
        )
        .await?;
    let techniques: Vec<String> = x.get(3);
    let meta = rule_meta::get(
        client,
        &a.rule_set_id,
        d.rule_set_version,
        &a.rule_id,
        d.rule_version,
    )
    .await?;
    let rule = match meta {
        Some(m) => RuleText {
            title: m.title,
            message: m.message,
            explain: m.explain,
            check: m.check,
            techniques: techniques.clone(),
        },
        None => RuleText {
            title: a.message.clone(),
            message: a.message.clone(),
            explain: None,
            check: None,
            techniques: Vec::new(),
        },
    };
    let commands = siblings(client, &a.agent_id, id).await?;
    let ids: Vec<i64> = commands.iter().map(|c| c.id).collect();
    let assignee: Option<String> = x.get(4);
    let case: Option<String> = x.get(6);
    let mut s = AlarmPageSummary {
        alarm: AlarmListRow {
            id,
            os_family: x.get(0),
            distribution: x.get(1),
            severity: AlarmSeverity::parse(&a.severity).unwrap_or(AlarmSeverity::Info),
            techniques,
            state: AlarmState::parse(&a.state).unwrap_or(AlarmState::Open),
            assignee: assignee.map(|id| (id, x.get(5))),
            case: case.map(|id| (id, x.get(7))),
            agent_id: a.agent_id.clone(),
            hostname: a.hostname,
            rule_set_id: a.rule_set_id.clone(),
            rule_id: a.rule_id.clone(),
            message: a.message,
            exe: a.exe,
            parent_exe: a.parent_exe,
            count: a.count,
            first_seen: a.first_seen,
            last_seen: a.last_seen,
            suppressed_by: a.suppressed_by,
        },
        rule_set_version: d.rule_set_version,
        rule_version: d.rule_version,
        confidence: d.confidence,
        process: d.process,
        ancestors: d.ancestors,
        received_at: d.received_at,
        triage: d.triage,
        rule,
        commands,
        hourly: hourly(client, &ids, now).await?,
        host_alarms: top_alarms(client, &a.agent_id, Some(id), HOST_ALARMS).await?,
        host_vulnerabilities: None,
        elsewhere: elsewhere(client, alarms, &a.agent_id, &a.rule_set_id, &a.rule_id).await?,
        host_groups: x.get(8),
        imported: x.get(2),
    };
    if vulnerabilities.is_some_and(|v| s.reaches(v)) {
        s.host_vulnerabilities = Some(top_vulnerabilities(client, &a.agent_id).await?);
    }
    Ok(Some(s))
}

/// Alarm `id` and every agent alarm on its host with the same rule set,
/// rule, program and parent (user decision 1). They share the host, so the
/// scope that reached `id` reaches them all.
async fn siblings(client: &Client, agent_id: &str, id: i64) -> Result<Vec<Command>, StoreError> {
    let rows = client
        .query(
            "SELECT s.id, s.agent_id,
                    CASE WHEN jsonb_typeof(s.process -> 'args') = 'array'
                         THEN ARRAY(SELECT jsonb_array_elements_text(s.process -> 'args'))
                         ELSE '{}' END,
                    s.count, s.first_seen, s.last_seen, s.state, s.suppressed_by,
                    cs.case_id::text, cs.number
             FROM alarms o JOIN alarms s
               ON s.agent_id = o.agent_id AND s.source = 'agent'
              AND s.rule_set_id = o.rule_set_id AND s.rule_id = o.rule_id
              AND s.process ->> 'exe' IS NOT DISTINCT FROM o.process ->> 'exe'
              AND s.ancestors -> 0 ->> 'exe' IS NOT DISTINCT FROM o.ancestors -> 0 ->> 'exe'
             LEFT JOIN case_items ci ON ci.kind = 'alarm' AND ci.active AND ci.ref = s.id::text
             LEFT JOIN cases cs ON cs.case_id = ci.case_id
             WHERE o.id = $1 AND o.agent_id = $2
             ORDER BY s.count DESC, s.id",
            &[&id, &agent_id],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let case: Option<String> = r.get(8);
            Command {
                id: r.get(0),
                agent_id: r.get(1),
                args: r.get(2),
                count: r.get(3),
                first_seen: r.get(4),
                last_seen: r.get(5),
                state: r.get(6),
                suppressed_by: r.get(7),
                case: case.map(|c| (c, r.get(9))),
            }
        })
        .collect())
}

/// Starts of `ids` per hour for the 24 hours ending with `now`'s, oldest
/// first. Hours are cut by `date_trunc` as ingest cuts them.
async fn hourly(client: &Client, ids: &[i64], now: DateTime<Utc>) -> Result<Vec<i64>, StoreError> {
    Ok(client
        .query(
            "SELECT COALESCE(sum(h.starts), 0)::bigint
             FROM generate_series(date_trunc('hour', $1::timestamptz) - interval '23 hours',
                                  date_trunc('hour', $1::timestamptz), interval '1 hour') g(hour)
             LEFT JOIN alarm_hourly_starts h ON h.hour = g.hour AND h.alarm_row_id = ANY($2)
             GROUP BY g.hour ORDER BY g.hour",
            &[&now, &ids],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect())
}

/// Other hosts in `scope` with an open, unsuppressed agent alarm from this
/// rule set and rule (ruling 9).
async fn elsewhere(
    client: &Client,
    scope: &AgentScope,
    agent_id: &str,
    rule_set_id: &str,
    rule_id: &str,
) -> Result<Elsewhere, StoreError> {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let row = client
        .query_one(
            &format!(
                "SELECT count(DISTINCT al.agent_id), count(*)
                 FROM alarms al JOIN agents a ON a.agent_id = al.agent_id
                 WHERE al.rule_set_id = $3 AND al.rule_id = $4 AND al.agent_id <> $5
                   AND al.source = 'agent' AND al.state = 'open' AND al.suppressed_by IS NULL
                   AND {visible}"
            ),
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &rule_set_id,
                &rule_id,
                &agent_id,
            ],
        )
        .await?;
    Ok(Elsewhere {
        hosts: row.get(0),
        open: row.get(1),
    })
}
