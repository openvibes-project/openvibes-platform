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
    console_triage::{self, TriageUpdate, fields_valid},
    vulnerability_triage::{self, VulnerabilityTriageUpdate},
};

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

/// A host reached through its rule or advisory (not named) that is already
/// closed keeps its decision when the change closes: "mitigate this
/// finding" must not turn its false positives into mitigated. Reopening
/// and named hosts change as asked.
fn spared(change: BulkChange<'_>, named: bool, current: &str) -> bool {
    matches!(change, BulkChange::State { state, .. } if state != "open")
        && !named
        && current != "open"
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

/// Applies `change` to compliance findings: each item is a rule (every host
/// in scope with a current finding of it) or one host's finding.
pub async fn compliance(
    client: &mut Client,
    scope: &AgentScope,
    items: &[(String, String, Option<String>)],
    change: BulkChange<'_>,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Result<BulkResult, BulkRefusal>, StoreError> {
    if let Err(refusal) = check(change, items.len(), now) {
        return Ok(Err(refusal));
    }
    let Some(matched) = expand_compliance(client, scope, items).await? else {
        return Ok(Err(BulkRefusal::Count));
    };
    let mut result = BulkResult::default();
    // A requested finding (or rule) that matched nothing in scope.
    for (set, rule, agent) in items {
        let hit = matched.iter().any(|(a, s, r)| {
            s == set && r == rule && agent.as_ref().is_none_or(|agent| agent == a)
        });
        if !hit {
            let id = agent
                .as_ref()
                .map_or_else(|| format!("{set}/{rule}"), |a| format!("{a}/{set}/{rule}"));
            result.skipped.push((id, "not found or out of scope"));
        }
    }
    for (agent, set, rule) in &matched {
        let (agent, set, rule) = (agent.clone(), set.clone(), rule.clone());
        let id = format!("{agent}/{set}/{rule}");
        let Some(current) = console_triage::get(client, &agent, &set, &rule).await? else {
            result.skipped.push((id, "not found or out of scope"));
            continue;
        };
        let named = items
            .iter()
            .any(|(s, r, a)| *s == set && *r == rule && a.as_deref() == Some(agent.as_str()));
        if spared(change, named, &current.state) {
            result.skipped.push((id, "already closed"));
            continue;
        }
        let (state, assignee, note, until) = match change {
            BulkChange::State {
                state,
                note,
                accepted_until,
            } => (
                state.to_owned(),
                current.assigned_to_username.clone(),
                note.map(str::to_owned),
                accepted_until,
            ),
            BulkChange::Assign(to) => (
                current.state.clone(),
                to.map(str::to_owned),
                current.note.clone(),
                current.accepted_until,
            ),
        };
        let outcome = console_triage::update(
            client,
            &agent,
            &set,
            &rule,
            current.version,
            &state,
            assignee.as_deref(),
            note.as_deref(),
            until,
            actor,
            now,
        )
        .await?;
        match outcome {
            TriageUpdate::Updated(_) => result.changed += 1,
            TriageUpdate::NotFound => result.skipped.push((id, "not found or out of scope")),
            TriageUpdate::Stale(_) => result
                .skipped
                .push((id, "changed by someone else meanwhile")),
            TriageUpdate::AssigneeUnavailable => result.skipped.push((id, "assignee unavailable")),
            TriageUpdate::InvalidTransition(_) | TriageUpdate::InvalidFields => {
                result.skipped.push((id, "refused"));
            }
        }
    }
    audit(client, actor, "finding.bulk_triage", change, &result).await?;
    Ok(Ok(result))
}

/// Applies `change` to vulnerabilities: each item is an advisory (every
/// host in scope where it is open) or one host's.
pub async fn vulnerabilities(
    client: &mut Client,
    scope: &AgentScope,
    items: &[(String, Option<String>)],
    change: BulkChange<'_>,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Result<BulkResult, BulkRefusal>, StoreError> {
    if let Err(refusal) = check(change, items.len(), now) {
        return Ok(Err(refusal));
    }
    let Some(pairs) = expand_vulnerabilities(client, scope, items).await? else {
        return Ok(Err(BulkRefusal::Count));
    };
    let current = vulnerability_triage::states(client, &pairs).await?;
    let mut result = BulkResult::default();
    // A requested vulnerability (or advisory) that matched nothing in scope.
    for (advisory, agent) in items {
        let hit = pairs
            .iter()
            .any(|(a, adv)| adv == advisory && agent.as_ref().is_none_or(|agent| agent == a));
        if !hit {
            let id = agent
                .as_ref()
                .map_or_else(|| advisory.clone(), |a| format!("{a}/{advisory}"));
            result.skipped.push((id, "not found or out of scope"));
        }
    }
    for (agent, advisory) in &pairs {
        let now_state = current
            .get(&(agent.clone(), advisory.clone()))
            .cloned()
            .unwrap_or_default();
        let named = items
            .iter()
            .any(|(adv, a)| adv == advisory && a.as_deref() == Some(agent.as_str()));
        if spared(change, named, &now_state.state) {
            result
                .skipped
                .push((format!("{agent}/{advisory}"), "already closed"));
            continue;
        }
        let (state, assignee, note, until) = match change {
            BulkChange::State {
                state,
                note,
                accepted_until,
            } => (
                state.to_owned(),
                now_state.assigned_to.clone(),
                note.map(str::to_owned),
                accepted_until,
            ),
            BulkChange::Assign(to) => (
                now_state.state.clone(),
                to.map(str::to_owned),
                now_state.note.clone(),
                now_state.accepted_until,
            ),
        };
        let outcome = vulnerability_triage::update(
            client,
            scope,
            agent,
            advisory,
            None,
            &state,
            assignee.as_deref(),
            note.as_deref(),
            until,
            actor,
            now,
        )
        .await?;
        let id = format!("{agent}/{advisory}");
        match outcome {
            VulnerabilityTriageUpdate::Updated(_) => result.changed += 1,
            VulnerabilityTriageUpdate::NotFound => {
                result.skipped.push((id, "not found or out of scope"))
            }
            VulnerabilityTriageUpdate::Stale(_) => {
                result
                    .skipped
                    .push((id, "changed by someone else meanwhile"));
            }
            VulnerabilityTriageUpdate::AssigneeUnavailable => {
                result.skipped.push((id, "assignee unavailable"));
            }
            VulnerabilityTriageUpdate::InvalidFields => result.skipped.push((id, "refused")),
        }
    }
    audit(client, actor, "vulnerability.bulk_triage", change, &result).await?;
    Ok(Ok(result))
}

/// The (agent, rule set, rule) findings these items name in scope: a rule
/// without a host is every host with a current finding of it. `None` when
/// they are more than [`MAX_ITEMS`].
pub async fn expand_compliance(
    client: &Client,
    scope: &AgentScope,
    items: &[(String, String, Option<String>)],
) -> Result<Option<Vec<(String, String, String)>>, StoreError> {
    let (sets, rules, agents): (Vec<&str>, Vec<&str>, Vec<Option<&str>>) = items.iter().fold(
        (Vec::new(), Vec::new(), Vec::new()),
        |(mut s, mut r, mut a), (set, rule, agent)| {
            s.push(set.as_str());
            r.push(rule.as_str());
            a.push(agent.as_deref());
            (s, r, a)
        },
    );
    let visible = agent_visibility("a.agent_id", "$4", "$5");
    let rows = client
        .query(
            &format!(
                "SELECT DISTINCT c.agent_id, c.rule_set_id, c.rule_id
                 FROM unnest($1::text[], $2::text[], $3::text[]) AS k(rule_set_id, rule_id, agent_id)
                 JOIN current_findings c ON c.rule_set_id = k.rule_set_id AND c.rule_id = k.rule_id
                     AND (k.agent_id IS NULL OR c.agent_id = k.agent_id)
                 JOIN agents a ON a.agent_id = c.agent_id
                 WHERE {visible}
                 ORDER BY 2, 3, 1 LIMIT {}",
                MAX_ITEMS + 1
            ),
            &[&sets, &rules, &agents, &scope.is_global(), &scope.group_ids()],
        )
        .await?;
    Ok((rows.len() <= MAX_ITEMS).then(|| {
        rows.iter()
            .map(|r| (r.get(0), r.get(1), r.get(2)))
            .collect()
    }))
}

/// The (agent, advisory) open vulnerabilities these items name in scope:
/// an advisory without a host is every host where it is open. `None` when
/// they are more than [`MAX_ITEMS`].
pub async fn expand_vulnerabilities(
    client: &Client,
    scope: &AgentScope,
    items: &[(String, Option<String>)],
) -> Result<Option<Vec<(String, String)>>, StoreError> {
    let (advisories, agents): (Vec<&str>, Vec<Option<&str>>) = items
        .iter()
        .map(|(adv, agent)| (adv.as_str(), agent.as_deref()))
        .unzip();
    let visible = agent_visibility("a.agent_id", "$3", "$4");
    let rows = client
        .query(
            &format!(
                "SELECT DISTINCT v.agent_id, v.advisory_id
                 FROM unnest($1::text[], $2::text[]) AS k(advisory_id, agent_id)
                 JOIN vulnerabilities v ON v.advisory_id = k.advisory_id AND v.fixed_at IS NULL
                     AND (k.agent_id IS NULL OR v.agent_id = k.agent_id)
                 JOIN agents a ON a.agent_id = v.agent_id
                 WHERE {visible}
                 ORDER BY 2, 1 LIMIT {}",
                MAX_ITEMS + 1
            ),
            &[&advisories, &agents, &scope.is_global(), &scope.group_ids()],
        )
        .await?;
    Ok((rows.len() <= MAX_ITEMS).then(|| rows.iter().map(|r| (r.get(0), r.get(1))).collect()))
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
