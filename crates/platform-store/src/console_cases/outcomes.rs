//! An item's outcome: how the work on it ended.

use chrono::{DateTime, Utc};
use serde_json::json;

use super::{
    CaseItem, OutcomeChange, Refusal, Viewer,
    close::lock_case,
    events::{audit, push_event, touch},
    items::lock_item,
    note_ok, refuse,
    visibility::read_items,
};
use crate::{Client, StoreError, console_read::AgentScope};

/// Sets, or with `None` clears, an item's outcome on an open case.
/// `resolved` needs the evidence to be gone; `false_positive` and
/// `accepted_risk` need a note. Hosts and software take no outcome.
pub async fn set_outcome(
    client: &mut Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
    item_id: &str,
    change: Option<&OutcomeChange<'_>>,
    now: DateTime<Utc>,
) -> Result<Result<CaseItem, Refusal>, StoreError> {
    if let Some(change) = change {
        if !matches!(
            change.outcome,
            "resolved" | "false_positive" | "accepted_risk"
        ) {
            return Ok(Err(Refusal::Invalid("outcome", "invalid_outcome")));
        }
        let needs_note = change.outcome != "resolved";
        match change.note {
            None if needs_note => return Ok(Err(Refusal::Invalid("note", "note_required"))),
            Some(note) if !note_ok(note) => {
                return Ok(Err(Refusal::Invalid("note", "invalid_note")));
            }
            _ => {}
        }
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
    if item.outcome.as_deref() != outcome || change.is_some() {
        tx.execute(
            "UPDATE case_items SET outcome = $2, outcome_note = $3 WHERE item_id = $1::text::uuid",
            &[&item_id, &outcome, &note],
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
                    "from": item.outcome, "to": outcome }),
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
