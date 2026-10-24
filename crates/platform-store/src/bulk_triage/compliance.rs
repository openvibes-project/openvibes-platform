//! Bulk triage of compliance findings: (rule set, rule, host?) items,
//! expanded to the (agent, rule set, rule) failing pairs in scope.

use chrono::{DateTime, Utc};

use super::{BulkChange, BulkRefusal, BulkResult, MAX_ITEMS, audit, check, spared};
use crate::{
    Client, StoreError,
    console_read::{AgentScope, agent_visibility},
    console_triage::{self, TriageUpdate},
};

/// One selected check row or finding: (rule set, rule, host?).
pub type Item = (String, String, Option<String>);

/// Applies `change` to compliance findings: each item is a rule (every host
/// in scope where it fails and is open) or one host's finding.
pub async fn compliance(
    client: &mut Client,
    scope: &AgentScope,
    items: &[Item],
    change: BulkChange<'_>,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Result<BulkResult, BulkRefusal>, StoreError> {
    compliance_open_only(client, scope, items, &[], change, actor, now).await
}

/// [`compliance`], where `open_only[i]` (missing: false) marks item `i` as a
/// check row's: a close or assign then changes its pairs only while failing
/// and open ("not open" otherwise), even on one named host. A rule-wide item
/// is always so; a reopen ignores the flag and keeps its own rules.
pub async fn compliance_open_only(
    client: &mut Client,
    scope: &AgentScope,
    items: &[Item],
    open_only: &[bool],
    change: BulkChange<'_>,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Result<BulkResult, BulkRefusal>, StoreError> {
    if let Err(refusal) = check(change, items.len(), now) {
        return Ok(Err(refusal));
    }
    // A close or assign on a rule-wide or check-row item reaches its failing,
    // open pairs only: ended or closed ones neither count toward the cap nor
    // are listed. A reopen and named findings expand as before.
    let reopen = matches!(change, BulkChange::State { state: "open", .. });
    let filtered: Vec<bool> = items
        .iter()
        .enumerate()
        .map(|(i, (_, _, agent))| {
            !reopen && (agent.is_none() || open_only.get(i).copied().unwrap_or(false))
        })
        .collect();
    let Some(matched) = rows(client, scope, items, &filtered, now, Mode::Open)
        .await?
        .map(|rows| {
            rows.iter()
                .map(|r| (r.get(0), r.get(1), r.get(2)))
                .collect::<Vec<(String, String, String)>>()
        })
    else {
        return Ok(Err(BulkRefusal::Count));
    };
    let mut result = BulkResult::default();
    // A requested finding (or rule) that matched nothing in scope; a filtered
    // one that fails somewhere in reach, with no open pair, is "not open".
    let missed: Vec<usize> = (0..items.len())
        .filter(|&i| {
            let (set, rule, agent) = &items[i];
            !matched.iter().any(|(a, s, r)| {
                s == set && r == rule && agent.as_ref().is_none_or(|agent| agent == a)
            })
        })
        .collect();
    let failing = if missed.iter().any(|&i| filtered[i]) {
        reaching(client, scope, items, now).await?
    } else {
        std::collections::HashSet::new()
    };
    for i in missed {
        let (set, rule, agent) = &items[i];
        let id = agent
            .as_ref()
            .map_or_else(|| format!("{set}/{rule}"), |a| format!("{a}/{set}/{rule}"));
        let reason = if filtered[i] && failing.contains(&i) {
            "not open"
        } else {
            "not found or out of scope"
        };
        result.skipped.push((id, reason));
    }
    for (agent, set, rule) in &matched {
        let id = format!("{agent}/{set}/{rule}");
        let Some(current) = console_triage::get(client, agent, set, rule).await? else {
            result.skipped.push((id, "not found or out of scope"));
            continue;
        };
        // A list row names its host without lifting the open rule, except
        // for a reopen.
        let named = items.iter().enumerate().any(|(i, (s, r, a))| {
            s == set
                && r == rule
                && a.as_deref() == Some(agent.as_str())
                && (reopen || !open_only.get(i).copied().unwrap_or(false))
        });
        // An expired accepted risk is open (when closing or assigning; a
        // reopen still sees its stored state and clears it).
        let open = current.state == "open"
            || (current.state == "accepted_risk"
                && current.accepted_until.is_some_and(|u| u <= now));
        if !named && !reopen && !open {
            result.skipped.push((id, "not open"));
            continue;
        }
        let effective = if open && !reopen {
            "open"
        } else {
            &current.state
        };
        if let Some(why) = spared(change, named, effective) {
            result.skipped.push((id, why));
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
            // An expired accepted risk is written back open: the update
            // refuses a past expiry.
            BulkChange::Assign(to) if effective == "open" && current.state != "open" => (
                "open".to_owned(),
                to.map(str::to_owned),
                current.note.clone(),
                None,
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
            agent,
            set,
            rule,
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

/// The (agent, rule set, rule) findings these items name in scope: a rule
/// without a host is every host with a current finding of it. A rule-wide
/// item, or one with `open_only[i]` (missing: false), reaches failing (not
/// ended) findings only, closed ones included. `None` when they are more
/// than [`MAX_ITEMS`].
pub async fn expand_compliance(
    client: &Client,
    scope: &AgentScope,
    items: &[Item],
    open_only: &[bool],
) -> Result<Option<Vec<(String, String, String)>>, StoreError> {
    let failing: Vec<bool> = items
        .iter()
        .enumerate()
        .map(|(i, (_, _, agent))| agent.is_none() || open_only.get(i).copied().unwrap_or(false))
        .collect();
    Ok(
        rows(client, scope, items, &failing, Utc::now(), Mode::Failing)
            .await?
            .map(|rows| {
                rows.iter()
                    .map(|r| (r.get(0), r.get(1), r.get(2)))
                    .collect()
            }),
    )
}

/// What [`rows`] asks for.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    /// Pairs; a filtered item keeps its failing, open ones.
    Open,
    /// Pairs; a filtered item keeps its failing ones, open or not.
    Failing,
    /// The 1-based indexes of the filtered items that reach any failing pair.
    Which,
}

/// The indexes of the items with any failing pair in scope, open or not.
async fn reaching(
    client: &Client,
    scope: &AgentScope,
    items: &[Item],
    now: DateTime<Utc>,
) -> Result<std::collections::HashSet<usize>, StoreError> {
    let all = vec![true; items.len()];
    let found = rows(client, scope, items, &all, now, Mode::Which).await?;
    Ok(found
        .unwrap_or_default()
        .iter()
        .map(|r| usize::try_from(r.get::<_, i64>(0) - 1).unwrap_or(usize::MAX))
        .collect())
}

/// The expansion query: pairs, or (`Mode::Which`) the 1-based indexes of the items
/// that reach any failing pair. `open[i]` keeps item `i` to its failing
/// pairs (by the list's [`crate::check_list_sql::failing`]) still open at `now` (no triage, open, or an expired accepted risk);
/// with `Mode::Which`, only the failing test applies.
async fn rows(
    client: &Client,
    scope: &AgentScope,
    items: &[Item],
    open: &[bool],
    now: DateTime<Utc>,
    mode: Mode,
) -> Result<Option<Vec<tokio_postgres::Row>>, StoreError> {
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
    let (select, order) = if mode == Mode::Which {
        ("k.i", String::new())
    } else {
        (
            "c.agent_id, c.rule_set_id, c.rule_id",
            format!("ORDER BY 2, 3, 1 LIMIT {}", MAX_ITEMS + 1),
        )
    };
    // The Compliance list's failing test (open, seen within its window), so
    // a row reaches exactly the pairs it counts.
    let failing = crate::check_list_sql::failing("$7").replace("f.", "c.");
    let still_open = if mode != Mode::Open {
        "$7::timestamptz IS NOT NULL"
    } else {
        "(t.state IS NULL OR t.state = 'open'
                       OR (t.state = 'accepted_risk' AND t.accepted_until <= $7))"
    };
    let rows = client
        .query(
            &format!(
                "SELECT DISTINCT {select}
                 FROM unnest($1::text[], $2::text[], $3::text[], $6::bool[])
                     WITH ORDINALITY AS k(rule_set_id, rule_id, agent_id, open_only, i)
                 JOIN current_findings c ON c.rule_set_id = k.rule_set_id AND c.rule_id = k.rule_id
                     AND (k.agent_id IS NULL OR c.agent_id = k.agent_id)
                 JOIN agents a ON a.agent_id = c.agent_id
                 LEFT JOIN console_finding_triage t ON t.agent_id = c.agent_id
                     AND t.rule_set_id = c.rule_set_id AND t.rule_id = c.rule_id
                 WHERE {visible}
                   AND (NOT k.open_only OR ({failing} AND {still_open}))
                 {order}"
            ),
            &[
                &sets,
                &rules,
                &agents,
                &scope.is_global(),
                &scope.group_ids(),
                &open,
                &now,
            ],
        )
        .await?;
    Ok((rows.len() <= MAX_ITEMS).then_some(rows))
}
