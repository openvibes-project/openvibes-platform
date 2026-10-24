//! Bulk triage (triage v2, spec `2026-10-10-bulk-triage-design.md` §3–6):
//! one change applied to up to [`MAX_ITEMS`] alarms, compliance findings or
//! vulnerabilities. Each item goes through the same single-item update
//! (scope, rules, history and audit unchanged); items out of scope, gone or
//! refused are skipped with a reason, never silently changed.

use chrono::{DateTime, Utc};

use crate::{
    Client, StoreError,
    console_alarms::{self, TriageChange, TriageOutcome},
    console_read::{AgentScope, agent_visibility},
    console_triage::fields_valid,
};

mod vulns;
pub use vulns::{expand_vulnerabilities, vulnerabilities, vulnerabilities_open_only};
mod compliance;
pub use compliance::{compliance, compliance_open_only, expand_compliance};

/// Most items one bulk action changes (after hosts are expanded).
// ponytail: one transaction per item keeps the single-item rules exact;
// 10,000 items take seconds. Batch the writes if that ever matters.
pub const MAX_ITEMS: usize = 10_000;

/// What a bulk action does to every item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BulkChange<'a> {
    /// A new state; a close needs a note, an accepted risk its expiry.
    State {
        /// `open`, `mitigated`, `accepted_risk` or `false_positive`.
        state: &'a str,
        /// The note on every item (required to close).
        note: Option<&'a str>,
        /// Accepted-risk expiry.
        accepted_until: Option<DateTime<Utc>>,
    },
    /// A new assignee (`None` unassigns); state and note stay.
    Assign(Option<&'a str>),
}

/// What happened.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BulkResult {
    /// Items changed (or already so).
    pub changed: usize,
    /// Items left alone: (item id, reason).
    pub skipped: Vec<(String, &'static str)>,
}

/// Why nothing was done.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BulkRefusal {
    /// No items, or more than [`MAX_ITEMS`].
    Count,
    /// The state, note or expiry breaks the rules.
    Fields,
}

/// Why a host reached through its rule or advisory (not named) is left
/// alone, if it is: an already closed one keeps its decision when the change
/// closes ("mitigate this finding" must not turn its false positives into
/// mitigated), and reopening skips the ones already open (no empty history
/// rows). Named hosts change as asked.
fn spared(change: BulkChange<'_>, named: bool, current: &str) -> Option<&'static str> {
    let BulkChange::State { state, .. } = change else {
        return None;
    };
    match (named, state == "open", current == "open") {
        (true, _, _) => None,
        (false, false, false) => Some("already closed"),
        (false, true, true) => Some("already open"),
        _ => None,
    }
}

fn check(change: BulkChange<'_>, count: usize, now: DateTime<Utc>) -> Result<(), BulkRefusal> {
    if count == 0 || count > MAX_ITEMS {
        return Err(BulkRefusal::Count);
    }
    if let BulkChange::State {
        state,
        note,
        accepted_until,
    } = change
        && (!fields_valid(state, note, accepted_until, now) || (state != "open" && note.is_none()))
    {
        return Err(BulkRefusal::Fields);
    }
    Ok(())
}

fn reason_alarm(outcome: &TriageOutcome) -> Option<&'static str> {
    match outcome {
        TriageOutcome::Updated(_) => None,
        TriageOutcome::NotFound => Some("not found or out of scope"),
        TriageOutcome::Stale => Some("changed by someone else meanwhile"),
        TriageOutcome::InvalidTransition | TriageOutcome::InvalidFields => Some("refused"),
        TriageOutcome::AssigneeUnavailable => Some("assignee unavailable"),
    }
}

/// Applies `change` to these alarms (row ids).
pub async fn alarms(
    client: &mut Client,
    scope: &AgentScope,
    ids: &[i64],
    change: BulkChange<'_>,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Result<BulkResult, BulkRefusal>, StoreError> {
    if let Err(refusal) = check(change, ids.len(), now) {
        return Ok(Err(refusal));
    }
    let visible = agent_visibility("a.agent_id", "$2", "$3");
    let rows = client
        .query(
            &format!(
                "SELECT al.id, al.triage_version, al.state, u.username, al.note, al.accepted_until
                 FROM alarms al JOIN agents a USING (agent_id)
                 LEFT JOIN console_users u ON u.user_id = al.assigned_to
                 WHERE al.id = ANY($1) AND {visible}"
            ),
            &[&ids, &scope.is_global(), &scope.group_ids()],
        )
        .await?;
    let mut result = BulkResult::default();
    let found: std::collections::HashSet<i64> = rows.iter().map(|r| r.get(0)).collect();
    result.skipped.extend(
        ids.iter()
            .filter(|id| !found.contains(id))
            .map(|id| (id.to_string(), "not found or out of scope")),
    );
    for row in &rows {
        let id: i64 = row.get(0);
        let (state, assignee, note, until): (
            String,
            Option<String>,
            Option<String>,
            Option<DateTime<Utc>>,
        ) = (row.get(2), row.get(3), row.get(4), row.get(5));
        let triage = match change {
            BulkChange::State {
                state,
                note,
                accepted_until,
            } => TriageChange {
                expected_version: row.get(1),
                state,
                assigned_to_username: assignee.as_deref(),
                note,
                accepted_until,
            },
            BulkChange::Assign(to) => TriageChange {
                expected_version: row.get(1),
                state: &state,
                assigned_to_username: to,
                note: note.as_deref(),
                accepted_until: until,
            },
        };
        let outcome = console_alarms::update_triage(client, scope, id, &triage, actor, now).await?;
        match reason_alarm(&outcome) {
            None => result.changed += 1,
            Some(reason) => result.skipped.push((id.to_string(), reason)),
        }
    }
    audit(client, actor, "alarm.bulk_triage", change, &result).await?;
    Ok(Ok(result))
}

/// One audit row per bulk action (each item also has its own).
async fn audit(
    client: &Client,
    actor: &str,
    action: &str,
    change: BulkChange<'_>,
    result: &BulkResult,
) -> Result<(), StoreError> {
    let what = match change {
        BulkChange::State { state, .. } => format!("state:{state}"),
        BulkChange::Assign(Some(to)) => format!("assign:{to}"),
        BulkChange::Assign(None) => "assign:none".to_owned(),
    };
    let changed = i64::try_from(result.changed).unwrap_or(i64::MAX);
    let skipped = i64::try_from(result.skipped.len()).unwrap_or(i64::MAX);
    client
        .execute(
            "INSERT INTO audit_log (actor, action, target, result, detail, actor_kind, actor_id,
                 actor_display, target_kind, target_id)
             VALUES ($1, $2, 'bulk_triage', 'success',
                 jsonb_build_object('change', $3::text, 'changed', $4::bigint,
                     'skipped', $5::bigint),
                 'user', $1, $1, 'bulk_triage', $2)",
            &[&actor, &action, &what, &changed, &skipped],
        )
        .await?;
    Ok(())
}
