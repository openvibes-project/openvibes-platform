//! Console reads and triage of threat alarms (P14), scoped to the
//! caller's agents like findings. An alarm outside the scope reads as
//! absent, never as forbidden.

use chrono::{DateTime, Utc};

use crate::{
    Client, StoreError,
    console_read::{AgentScope, agent_visibility},
    console_triage::{assignee, fields_valid, transition_allowed},
};

/// One alarm in the list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlarmSummary {
    /// The platform's id (the console's key).
    pub id: i64,
    /// Agent that raised it.
    pub agent_id: String,
    /// The agent's hostname, when known.
    pub hostname: Option<String>,
    /// Rule set of the rule.
    pub rule_set_id: String,
    /// Rule that raised it.
    pub rule_id: String,
    /// Finding severity name.
    pub severity: String,
    /// The rule's message.
    pub message: String,
    /// The process's exe.
    pub exe: String,
    /// Its parent's exe, when known.
    pub parent_exe: Option<String>,
    /// How many starts matched.
    pub count: i64,
    /// First start that matched.
    pub first_seen: DateTime<Utc>,
    /// Latest start that matched.
    pub last_seen: DateTime<Utc>,
    /// Triage state.
    pub state: String,
    /// The suppression that closed it at insert.
    pub suppressed_by: Option<i64>,
}

/// An alarm with its process tree and triage.
#[derive(Clone, Debug, PartialEq)]
pub struct AlarmDetail {
    /// The list fields.
    pub summary: AlarmSummary,
    /// Rule set version.
    pub rule_set_version: i64,
    /// Rule version.
    pub rule_version: i64,
    /// 0 to 100.
    pub confidence: i16,
    /// The process (masked args) as the agent sent it.
    pub process: serde_json::Value,
    /// Its ancestors, nearest first, as sent.
    pub ancestors: serde_json::Value,
    /// When ingest stored it.
    pub received_at: DateTime<Utc>,
    /// Current triage.
    pub triage: AlarmTriage,
}

/// Triage of one alarm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlarmTriage {
    /// Workflow state.
    pub state: String,
    /// Assignee's username.
    pub assigned_to_username: Option<String>,
    /// Operator note.
    pub note: Option<String>,
    /// Accepted-risk expiry.
    pub accepted_until: Option<DateTime<Utc>>,
    /// Write version for If-Match.
    pub version: i64,
    /// Last change.
    pub updated_at: Option<DateTime<Utc>>,
    /// Who changed it (`ingest` for a suppression or a recurrence).
    pub updated_by: Option<String>,
}

/// List filters; `None` matches everything.
#[derive(Clone, Debug, Default)]
pub struct AlarmFilters {
    /// Exact agent.
    pub agent_id: Option<String>,
    /// Exact rule.
    pub rule_id: Option<String>,
    /// Exact severity.
    pub severity: Option<String>,
    /// Exact triage state.
    pub state: Option<String>,
    /// Include alarms closed by a suppression (hidden by default).
    pub suppressed: bool,
}

/// Where the next page starts: after this `(last_seen, id)`.
pub type AlarmCursor = (DateTime<Utc>, i64);

const SUMMARY: &str = "al.id, al.agent_id, a.hostname, al.rule_set_id, al.rule_id, al.severity,
    al.message, al.process->>'exe', al.ancestors->0->>'exe', al.count, al.first_seen,
    al.last_seen, al.state, al.suppressed_by";

fn summary(row: &tokio_postgres::Row) -> AlarmSummary {
    AlarmSummary {
        id: row.get(0),
        agent_id: row.get(1),
        hostname: row.get(2),
        rule_set_id: row.get(3),
        rule_id: row.get(4),
        severity: row.get(5),
        message: row.get(6),
        exe: row.get::<_, Option<String>>(7).unwrap_or_default(),
        parent_exe: row.get(8),
        count: row.get(9),
        first_seen: row.get(10),
        last_seen: row.get(11),
        state: row.get(12),
        suppressed_by: row.get(13),
    }
}

fn scope_params(scope: &AgentScope) -> (bool, Vec<String>) {
    match scope {
        AgentScope::Global => (true, Vec::new()),
        AgentScope::AssetGroups(groups) => (false, groups.clone()),
    }
}

/// Newest `last_seen` first, tie-broken by id. A resend moves `last_seen`,
/// so a row can shift between pages: the list is a live view.
pub async fn list(
    client: &Client,
    scope: &AgentScope,
    filters: &AlarmFilters,
    after: Option<AlarmCursor>,
    limit: i64,
) -> Result<Vec<AlarmSummary>, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let query = format!(
        "SELECT {SUMMARY} FROM alarms al JOIN agents a ON a.agent_id = al.agent_id
         WHERE {visible}
           AND ($3::text IS NULL OR al.agent_id = $3)
           AND ($4::text IS NULL OR al.rule_id = $4)
           AND ($5::text IS NULL OR al.severity = $5)
           AND ($6::text IS NULL OR al.state = $6)
           AND ($7 OR al.suppressed_by IS NULL)
           AND ($8::timestamptz IS NULL OR (al.last_seen, al.id) < ($8, $9))
         ORDER BY al.last_seen DESC, al.id DESC LIMIT $10"
    );
    let (cursor_at, cursor_id) = after.map_or((None, 0), |(at, id)| (Some(at), id));
    let rows = client
        .query(
            &query,
            &[
                &global,
                &groups,
                &filters.agent_id,
                &filters.rule_id,
                &filters.severity,
                &filters.state,
                &filters.suppressed,
                &cursor_at,
                &cursor_id,
                &limit,
            ],
        )
        .await?;
    Ok(rows.iter().map(summary).collect())
}

/// One alarm by the platform's id, if the caller may see it.
pub async fn detail(
    client: &Client,
    scope: &AgentScope,
    id: i64,
) -> Result<Option<AlarmDetail>, StoreError> {
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let query = format!(
        "SELECT {SUMMARY}, al.rule_set_version, al.rule_version, al.confidence, al.process,
            al.ancestors, al.received_at, u.username, al.note, al.accepted_until,
            al.triage_version, al.triage_updated_at, al.triage_updated_by
         FROM alarms al JOIN agents a ON a.agent_id = al.agent_id
         LEFT JOIN console_users u ON u.user_id = al.assigned_to
         WHERE al.id = $3 AND {visible}"
    );
    let row = client.query_opt(&query, &[&global, &groups, &id]).await?;
    Ok(row.map(|row| {
        let summary = summary(&row);
        AlarmDetail {
            triage: AlarmTriage {
                state: summary.state.clone(),
                assigned_to_username: row.get(20),
                note: row.get(21),
                accepted_until: row.get(22),
                version: row.get(23),
                updated_at: row.get(24),
                updated_by: row.get(25),
            },
            summary,
            rule_set_version: row.get(14),
            rule_version: row.get(15),
            confidence: row.get(16),
            process: row.get(17),
            ancestors: row.get(18),
            received_at: row.get(19),
        }
    }))
}

/// A triage change request.
#[derive(Clone, Debug)]
pub struct TriageChange<'a> {
    /// The If-Match version.
    pub expected_version: i64,
    /// New state.
    pub state: &'a str,
    /// Assignee's username.
    pub assigned_to_username: Option<&'a str>,
    /// Note (required for completed states).
    pub note: Option<&'a str>,
    /// Accepted-risk expiry (required for accepted risk, in the future).
    pub accepted_until: Option<DateTime<Utc>>,
}

/// Outcome of [`update_triage`]; the same rules as findings triage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TriageOutcome {
    /// Saved (or already so).
    Updated(AlarmTriage),
    /// Absent or outside the caller's scope.
    NotFound,
    /// The version changed since the caller read it.
    Stale,
    /// The findings workflow does not allow this step.
    InvalidTransition,
    /// Note or expiry breaks the state's rules.
    InvalidFields,
    /// The assignee is not an enabled analyst or admin.
    AssigneeUnavailable,
}

/// Changes an alarm's triage with a version check, history and audit, in
/// one transaction.
pub async fn update_triage(
    client: &mut Client,
    scope: &AgentScope,
    id: i64,
    change: &TriageChange<'_>,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<TriageOutcome, StoreError> {
    let TriageChange {
        expected_version,
        state,
        assigned_to_username,
        note,
        accepted_until,
    } = *change;
    if !fields_valid(state, note, accepted_until, now)
        || (matches!(state, "mitigated" | "accepted_risk" | "false_positive") && note.is_none())
    {
        return Ok(TriageOutcome::InvalidFields);
    }
    let (global, groups) = scope_params(scope);
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt(
            &format!(
                "SELECT al.first_seen_day, al.state, al.triage_version, al.assigned_to::text,
                    al.note, al.accepted_until
                 FROM alarms al JOIN agents a ON a.agent_id = al.agent_id
                 WHERE al.id = $3 AND {visible} FOR UPDATE OF al"
            ),
            &[&global, &groups, &id],
        )
        .await?
    else {
        return Ok(TriageOutcome::NotFound);
    };
    let day: chrono::NaiveDate = row.get(0);
    let previous: String = row.get(1);
    let version: i64 = row.get(2);
    if version != expected_version {
        return Ok(TriageOutcome::Stale);
    }
    if !transition_allowed(&previous, state) {
        return Ok(TriageOutcome::InvalidTransition);
    }
    let assignee = match assigned_to_username {
        Some(username) => match assignee(&tx, username).await? {
            Some(found) => Some(found),
            None => return Ok(TriageOutcome::AssigneeUnavailable),
        },
        None => None,
    };
    let assigned_id = assignee.as_ref().map(|(id, _)| id.clone());
    let unchanged = previous == state
        && row.get::<_, Option<String>>(3) == assigned_id
        && row.get::<_, Option<String>>(4).as_deref() == note
        && row.get::<_, Option<DateTime<Utc>>>(5) == accepted_until;
    let triage =
        |version: i64, updated_at: Option<DateTime<Utc>>, by: Option<String>| AlarmTriage {
            state: state.to_owned(),
            assigned_to_username: assignee.as_ref().map(|(_, name)| name.clone()),
            note: note.map(str::to_owned),
            accepted_until,
            version,
            updated_at,
            updated_by: by,
        };
    if unchanged {
        return Ok(TriageOutcome::Updated(triage(version, None, None)));
    }
    let next = version + 1;
    tx.execute(
        "UPDATE alarms SET state = $3, assigned_to = $4::text::uuid, note = $5,
            accepted_until = $6, triage_version = $7, triage_updated_at = $8,
            triage_updated_by = $9
         WHERE id = $1 AND first_seen_day = $2",
        &[
            &id,
            &day,
            &state,
            &assigned_id,
            &note,
            &accepted_until,
            &next,
            &now,
            &actor_id,
        ],
    )
    .await?;
    tx.execute(
        "INSERT INTO alarm_triage_history (first_seen_day, alarm_row_id, from_state, to_state,
            assigned_to, accepted_until, note, changed_at, changed_by)
         VALUES ($1, $2, $3, $4, $5::text::uuid, $6, $7, $8, $9)",
        &[
            &day,
            &id,
            &previous,
            &state,
            &assigned_id,
            &accepted_until,
            &note,
            &now,
            &actor_id,
        ],
    )
    .await?;
    tx.execute(
        "INSERT INTO audit_log (actor, action, target, result, detail, actor_kind, actor_id,
            actor_display, target_kind, target_id)
         VALUES ($1, 'alarm.triage.changed', 'alarm_triage', 'success',
            jsonb_build_object('from_state', $2::text, 'to_state', $3::text,
                'version', $4::bigint), 'user', $1, $1, 'alarm', $5)",
        &[&actor_id, &previous, &state, &next, &id.to_string()],
    )
    .await?;
    tx.commit().await?;
    Ok(TriageOutcome::Updated(triage(
        next,
        Some(now),
        Some(actor_id.to_owned()),
    )))
}
