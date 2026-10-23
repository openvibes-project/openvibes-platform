//! Bulk triage of vulnerabilities: (advisory, host?) items, expanded to
//! the (agent, advisory) pairs in scope.

use chrono::{DateTime, Utc};

use super::{BulkChange, BulkRefusal, BulkResult, MAX_ITEMS, audit, check, spared};
use crate::{
    Client, StoreError,
    console_read::{AgentScope, agent_visibility},
    vulnerability_triage::{self, VulnerabilityTriageUpdate},
};

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
    vulnerabilities_open_only(client, scope, items, &[], change, actor, now).await
}

/// [`vulnerabilities`], where `open_only[i]` (missing: false) marks item `i`
/// as a list row's: a close or assign then changes its pairs only while
/// open ("not open" otherwise), even on one named host. A reopen ignores it.
pub async fn vulnerabilities_open_only(
    client: &mut Client,
    scope: &AgentScope,
    items: &[(String, Option<String>)],
    open_only: &[bool],
    change: BulkChange<'_>,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Result<BulkResult, BulkRefusal>, StoreError> {
    if let Err(refusal) = check(change, items.len(), now) {
        return Ok(Err(refusal));
    }
    // A close or assign on an advisory-wide or list-row item reaches its
    // open pairs only, so closed ones neither count toward the cap nor are
    // listed as skipped; a reopen and named pairs expand as before.
    let reopen = matches!(change, BulkChange::State { state: "open", .. });
    let filtered: Vec<bool> = items
        .iter()
        .enumerate()
        .map(|(i, (_, agent))| {
            !reopen && (agent.is_none() || open_only.get(i).copied().unwrap_or(false))
        })
        .collect();
    let Some(pairs) = expand(client, scope, items, &filtered, now).await? else {
        return Ok(Err(BulkRefusal::Count));
    };
    let current = vulnerability_triage::states(client, &pairs).await?;
    let mut result = BulkResult::default();
    // A requested vulnerability (or advisory) that matched nothing in scope;
    // a filtered one that has pairs, all closed, is "not open".
    let missed: Vec<usize> = (0..items.len())
        .filter(|&i| {
            let (advisory, agent) = &items[i];
            !pairs
                .iter()
                .any(|(a, adv)| adv == advisory && agent.as_ref().is_none_or(|agent| agent == a))
        })
        .collect();
    let closed = if missed.iter().any(|&i| filtered[i]) {
        reaching(client, scope, items, now).await?
    } else {
        std::collections::HashSet::new()
    };
    for i in missed {
        let (advisory, agent) = &items[i];
        let id = agent
            .as_ref()
            .map_or_else(|| advisory.clone(), |a| format!("{a}/{advisory}"));
        let reason = if filtered[i] && closed.contains(&i) {
            "not open"
        } else {
            "not found or out of scope"
        };
        result.skipped.push((id, reason));
    }
    for (agent, advisory) in &pairs {
        let now_state = current
            .get(&(agent.clone(), advisory.clone()))
            .cloned()
            .unwrap_or_default();
        // A CVE row acts on its open pairs only (an expired accepted risk is
        // open); a reopen keeps its own rule below. A list row's item names
        // its host without lifting that (`open_only`), except for a reopen.
        // The expansion already left closed ones out; this guards a race.
        let named = items.iter().enumerate().any(|(i, (adv, a))| {
            adv == advisory
                && a.as_deref() == Some(agent.as_str())
                && (reopen || !open_only.get(i).copied().unwrap_or(false))
        });
        let open = now_state.state == "open"
            || (now_state.state == "accepted_risk"
                && now_state.accepted_until.is_some_and(|u| u <= now));
        if !named && !reopen && !open {
            result
                .skipped
                .push((format!("{agent}/{advisory}"), "not open"));
            continue;
        }
        // An expired accepted risk is open when closing or assigning; a reopen
        // still sees its stored state and clears it, as before.
        let effective = if open && !reopen {
            "open"
        } else {
            &now_state.state
        };
        if let Some(why) = spared(change, named, effective) {
            result.skipped.push((format!("{agent}/{advisory}"), why));
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
            // An expired accepted risk is open: write it back open, as the
            // update refuses a past expiry.
            BulkChange::Assign(to) if effective == "open" && now_state.state != "open" => (
                "open".to_owned(),
                to.map(str::to_owned),
                now_state.note.clone(),
                None,
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

/// The (agent, advisory) open vulnerabilities these items name in scope:
/// an advisory without a host is every host where it is open. `None` when
/// they are more than [`MAX_ITEMS`].
pub async fn expand_vulnerabilities(
    client: &Client,
    scope: &AgentScope,
    items: &[(String, Option<String>)],
) -> Result<Option<Vec<(String, String)>>, StoreError> {
    expand(client, scope, items, &vec![false; items.len()], Utc::now()).await
}

/// [`expand_vulnerabilities`], where `open[i]` keeps item `i` to its pairs
/// still open at `now` (no triage, open, or an expired accepted risk).
async fn expand(
    client: &Client,
    scope: &AgentScope,
    items: &[(String, Option<String>)],
    open: &[bool],
    now: DateTime<Utc>,
) -> Result<Option<Vec<(String, String)>>, StoreError> {
    let rows = vuln_rows(client, scope, items, open, now, false).await?;
    Ok((rows.len() <= MAX_ITEMS).then(|| rows.iter().map(|r| (r.get(0), r.get(1))).collect()))
}

/// The indexes of the items with any unfixed pair in scope, open or not.
async fn reaching(
    client: &Client,
    scope: &AgentScope,
    items: &[(String, Option<String>)],
    now: DateTime<Utc>,
) -> Result<std::collections::HashSet<usize>, StoreError> {
    let rows = vuln_rows(client, scope, items, &vec![false; items.len()], now, true).await?;
    Ok(rows
        .iter()
        .map(|r| usize::try_from(r.get::<_, i64>(0) - 1).unwrap_or(usize::MAX))
        .collect())
}

/// The expansion query: pairs, or (`which`) the 1-based indexes of the
/// items that reach any.
async fn vuln_rows(
    client: &Client,
    scope: &AgentScope,
    items: &[(String, Option<String>)],
    open: &[bool],
    now: DateTime<Utc>,
    which: bool,
) -> Result<Vec<tokio_postgres::Row>, StoreError> {
    let (advisories, agents): (Vec<&str>, Vec<Option<&str>>) = items
        .iter()
        .map(|(adv, agent)| (adv.as_str(), agent.as_deref()))
        .unzip();
    let visible = agent_visibility("a.agent_id", "$3", "$4");
    let (select, order) = if which {
        ("k.i", String::new())
    } else {
        (
            "v.agent_id, v.advisory_id",
            format!("ORDER BY 2, 1 LIMIT {}", MAX_ITEMS + 1),
        )
    };
    Ok(client
        .query(
            &format!(
                "SELECT DISTINCT {select}
                 FROM unnest($1::text[], $2::text[], $5::bool[])
                     WITH ORDINALITY AS k(advisory_id, agent_id, open_only, i)
                 JOIN vulnerabilities v ON v.advisory_id = k.advisory_id AND v.fixed_at IS NULL
                     AND (k.agent_id IS NULL OR v.agent_id = k.agent_id)
                 JOIN agents a ON a.agent_id = v.agent_id
                 LEFT JOIN vulnerability_triage t
                     ON t.agent_id = v.agent_id AND t.advisory_id = v.advisory_id
                 WHERE {visible} AND (NOT k.open_only OR t.state IS NULL OR t.state = 'open'
                     OR (t.state = 'accepted_risk' AND t.accepted_until <= $6))
                 {order}"
            ),
            &[
                &advisories,
                &agents,
                &scope.is_global(),
                &scope.group_ids(),
                &open,
                &now,
            ],
        )
        .await?)
}
