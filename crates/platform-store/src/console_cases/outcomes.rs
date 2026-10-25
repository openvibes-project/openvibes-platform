//! An item's outcome: how the work on it ended.

use chrono::{DateTime, Utc};
use serde_json::json;

use super::{
    CaseItem, MAX_ACCEPT_DAYS, OUTCOMES, OutcomeChange, Refusal, Viewer,
    close::lock_case,
    events::{audit, push_event, touch},
    items::lock_item,
    note_ok, refuse,
    visibility::read_items,
};
use crate::{Client, StoreError, console_read::AgentScope};

/// Checks an outcome's own fields: a known outcome, a note for all but
/// `resolved`, and for `accepted_risk` alone a date in the next
/// [`MAX_ACCEPT_DAYS`] days.
fn outcome_valid(
    change: &OutcomeChange<'_>,
    now: DateTime<Utc>,
) -> Result<(), (&'static str, &'static str)> {
    if !OUTCOMES.contains(&change.outcome) {
        return Err(("outcome", "invalid_outcome"));
    }
    match change.note {
        None if change.outcome != "resolved" => return Err(("note", "note_required")),
        Some(note) if !note_ok(note) => return Err(("note", "invalid_note")),
        _ => {}
    }
    match (change.outcome == "accepted_risk", change.outcome_until) {
        (true, None) => Err(("outcome_until", "outcome_until_required")),
        (true, Some(until)) if until <= now => Err(("outcome_until", "outcome_until_past")),
        (true, Some(until)) if until > now + chrono::Duration::days(MAX_ACCEPT_DAYS) => {
            Err(("outcome_until", "outcome_until_too_far"))
        }
        (false, Some(_)) => Err(("outcome_until", "outcome_until_not_allowed")),
        _ => Ok(()),
    }
}

/// Sets, or with `None` clears, an item's outcome on an open case.
/// `resolved` needs the evidence to be gone; every other outcome needs a
/// note, and `accepted_risk` its re-open date. Hosts and software take no
/// outcome.
pub async fn set_outcome(
    client: &mut Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
    item_id: &str,
    change: Option<&OutcomeChange<'_>>,
    now: DateTime<Utc>,
) -> Result<Result<CaseItem, Refusal>, StoreError> {
    if let Some(Err((field, code))) = change.map(|change| outcome_valid(change, now)) {
        return Ok(Err(Refusal::Invalid(field, code)));
    }
    let viewer = Viewer::new(scope, user_id);
    let tx = client.transaction().await?;
    let Some(current) = lock_case(&tx, &viewer, case_id).await? else {
        return refuse(tx, Refusal::NotFound).await;
    };
    if current.status == "closed" {
        return refuse(tx, Refusal::Closed).await;
    }
    let Some(item) = lock_item(&tx, &viewer, case_id, item_id).await? else {
        return refuse(tx, Refusal::ItemNotFound).await;
    };
    if !item.kind.exclusive() {
        return refuse(tx, Refusal::Invalid("outcome", "outcome_not_applicable")).await;
    }
    if change.is_some_and(|change| change.outcome == "resolved") && !item.gone {
        return refuse(tx, Refusal::EvidencePresent).await;
    }
    let outcome = change.map(|change| change.outcome);
    let note = change.and_then(|change| change.note);
    let until = change.and_then(|change| change.outcome_until);
    if item.outcome.as_deref() != outcome || change.is_some() {
        tx.execute(
            "UPDATE case_items SET outcome = $2, outcome_note = $3, outcome_until = $4
             WHERE item_id = $1::text::uuid",
            &[&item_id, &outcome, &note, &until],
        )
        .await?;
        push_event(
            &tx,
            case_id,
            now,
            Some(user_id),
            "item_outcome",
            note,
            json!({ "item_id": item_id, "item_kind": item.kind.as_str(),
                    "item_ref": item.reference, "item_agent_id": item.agent_id,
                    "from": item.outcome, "to": outcome,
                    "until": until.map(|at| at.to_rfc3339()) }),
        )
        .await?;
        touch(&tx, case_id, now).await?;
        audit(
            &tx,
            Some(user_id),
            "case.item.outcome",
            case_id,
            json!({ "number": current.number, "kind": item.kind.as_str(),
                    "ref": item.reference, "outcome": outcome }),
        )
        .await?;
    }
    let mut items = read_items(&tx, &viewer, case_id, Some(item_id)).await?;
    let Some(saved) = items.pop() else {
        return Err(StoreError::Query);
    };
    tx.commit().await?;
    Ok(Ok(saved))
}
