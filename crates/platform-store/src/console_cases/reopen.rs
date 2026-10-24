//! The lazy reopen checks, run as the platform.

use chrono::{DateTime, Utc};
use serde_json::json;

use super::{
    EVIDENCE_WATCH_DAYS, REOPEN_BATCH,
    events::{audit, push_event},
    unique_violation,
    visibility::item_gone,
};
use crate::{Client, StoreError};

/// Reopens recently closed cases whose `resolved` evidence has come back,
/// as the platform (audit actor `system`).
///
/// Only cases closed within [`EVIDENCE_WATCH_DAYS`] are looked at, which
/// keeps the check bounded, and only items with the outcome `resolved`:
/// `false_positive` and `accepted_risk` are decisions, not evidence (accepted
/// risk reopens on its date, see [`reopen_expired`]). Each returning item
/// loses its outcome, so someone decides again; the other outcomes stay.
/// A case with an item that has since joined another open case is left
/// closed. The timeline gets one `reopened` entry that names no item, and
/// an `item_outcome` entry per returning item, which, like every item entry,
/// only those who can see the item are shown. Returns how many reopened.
pub async fn reopen_evidence_returned(
    client: &mut Client,
    now: DateTime<Utc>,
) -> Result<u32, StoreError> {
    let since = now - chrono::Duration::days(EVIDENCE_WATCH_DAYS);
    let gone = item_gone();
    let returned = format!(
        "i.outcome = 'resolved' AND i.kind IN ('alarm', 'compliance_finding', 'vulnerability')
         AND NOT ({gone})"
    );
    let due = client
        .query(
            &format!(
                "SELECT c.case_id::text FROM cases c
                 WHERE c.status = 'closed' AND c.closed_at >= $1
                   AND EXISTS (SELECT 1 FROM case_items i
                               WHERE i.case_id = c.case_id AND {returned})
                 ORDER BY c.closed_at DESC LIMIT $2"
            ),
            &[&since, &REOPEN_BATCH],
        )
        .await?;
    let mut reopened = 0;
    for row in due {
        let case_id: String = row.get(0);
        let tx = client.transaction().await?;
        let locked = tx
            .query_opt(
                "SELECT number FROM cases
                 WHERE case_id = $1::text::uuid AND status = 'closed' AND closed_at >= $2
                 FOR UPDATE SKIP LOCKED",
                &[&case_id, &since],
            )
            .await?;
        let Some(locked) = locked else {
            tx.rollback().await?;
            continue;
        };
        let number: i64 = locked.get(0);
        let items = tx
            .query(
                &format!(
                    "SELECT i.item_id::text, i.kind, i.ref, i.agent_id FROM case_items i
                     WHERE i.case_id = $1::text::uuid AND {returned}
                     ORDER BY i.seq"
                ),
                &[&case_id],
            )
            .await?;
        if items.is_empty() {
            tx.rollback().await?;
            continue;
        }
        let taken = tx
            .query_opt(
                "SELECT 1 FROM case_items mine
                 JOIN case_items o ON o.kind = mine.kind AND o.ref = mine.ref AND o.active
                      AND o.case_id <> mine.case_id
                 WHERE mine.case_id = $1::text::uuid
                   AND mine.kind IN ('alarm', 'compliance_finding', 'vulnerability')
                 LIMIT 1",
                &[&case_id],
            )
            .await?;
        if taken.is_some() {
            tx.rollback().await?;
            continue;
        }
        let ids: Vec<String> = items.iter().map(|item| item.get(0)).collect();
        let activated = tx
            .execute(
                "UPDATE case_items SET active = true,
                    outcome = CASE WHEN item_id::text = ANY($2) THEN NULL ELSE outcome END,
                    outcome_note = CASE WHEN item_id::text = ANY($2) THEN NULL
                                        ELSE outcome_note END
                 WHERE case_id = $1::text::uuid",
                &[&case_id, &ids],
            )
            .await;
        match activated {
            Ok(_) => {}
            // A concurrent request took one of the items: leave it closed.
            Err(error) if unique_violation(&error) => {
                tx.rollback().await?;
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        let previous: Option<String> = tx
            .query_one(
                "SELECT resolution FROM cases WHERE case_id = $1::text::uuid",
                &[&case_id],
            )
            .await?
            .get(0);
        tx.execute(
            "UPDATE cases SET status = 'open', resolution = NULL, resolution_note = NULL,
                accepted_until = NULL, closed_at = NULL, version = version + 1,
                updated_at = $2
             WHERE case_id = $1::text::uuid",
            &[&case_id, &now],
        )
        .await?;
        push_event(
            &tx,
            &case_id,
            now,
            None,
            "reopened",
            None,
            json!({ "reason": "evidence_returned", "status": "open",
                    "previous_resolution": previous }),
        )
        .await?;
        let mut named = Vec::with_capacity(items.len());
        for item in &items {
            let (item_id, kind, reference, agent_id): (String, String, String, Option<String>) =
                (item.get(0), item.get(1), item.get(2), item.get(3));
            push_event(
                &tx,
                &case_id,
                now,
                None,
                "item_outcome",
                None,
                json!({ "item_id": item_id, "item_kind": kind, "item_ref": reference,
                        "item_agent_id": agent_id, "from": "resolved", "to": null,
                        "reason": "evidence_returned" }),
            )
            .await?;
            named.push(json!({ "kind": kind, "ref": reference }));
        }
        audit(
            &tx,
            None,
            "case.reopen",
            &case_id,
            json!({ "number": number, "reason": "evidence_returned", "items": named }),
        )
        .await?;
        tx.commit().await?;
        reopened += 1;
    }
    Ok(reopened)
}

/// Both lazy reopen checks, for the console to run before it lists or reads
/// cases: accepted risk that has run out, and evidence that has returned.
pub async fn reopen_due(client: &mut Client, now: DateTime<Utc>) -> Result<u32, StoreError> {
    Ok(reopen_expired(client, now).await? + reopen_evidence_returned(client, now).await?)
}

/// Reopens closed cases whose accepted risk has run out, as the platform
/// (audit actor `system`). Items whose acceptance expired lose that
/// outcome, so someone decides again. A case with an item that has since
/// joined another open case is left closed. Returns how many reopened.
pub async fn reopen_expired(client: &mut Client, now: DateTime<Utc>) -> Result<u32, StoreError> {
    let due = client
        .query(
            "SELECT case_id::text FROM cases
             WHERE status = 'closed' AND resolution = 'accepted_risk' AND accepted_until <= $1
             ORDER BY accepted_until LIMIT 100",
            &[&now],
        )
        .await?;
    let mut reopened = 0;
    for row in due {
        let case_id: String = row.get(0);
        let tx = client.transaction().await?;
        let locked = tx
            .query_opt(
                "SELECT number FROM cases
                 WHERE case_id = $1::text::uuid AND status = 'closed'
                   AND resolution = 'accepted_risk' AND accepted_until <= $2
                 FOR UPDATE SKIP LOCKED",
                &[&case_id, &now],
            )
            .await?;
        let Some(locked) = locked else {
            tx.rollback().await?;
            continue;
        };
        let number: i64 = locked.get(0);
        let taken = tx
            .query_opt(
                "SELECT 1 FROM case_items mine
                 JOIN case_items o ON o.kind = mine.kind AND o.ref = mine.ref AND o.active
                      AND o.case_id <> mine.case_id
                 WHERE mine.case_id = $1::text::uuid
                   AND mine.kind IN ('alarm', 'compliance_finding', 'vulnerability')
                 LIMIT 1",
                &[&case_id],
            )
            .await?;
        if taken.is_some() {
            tx.rollback().await?;
            continue;
        }
        let activated = tx
            .execute(
                "UPDATE case_items SET active = true,
                    outcome = CASE WHEN outcome = 'accepted_risk' THEN NULL ELSE outcome END,
                    outcome_note = CASE WHEN outcome = 'accepted_risk' THEN NULL ELSE outcome_note END
                 WHERE case_id = $1::text::uuid",
                &[&case_id],
            )
            .await;
        match activated {
            Ok(_) => {}
            // A concurrent request took one of the items: leave it closed.
            Err(error) if unique_violation(&error) => {
                tx.rollback().await?;
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        tx.execute(
            "UPDATE cases SET status = 'open', resolution = NULL, resolution_note = NULL,
                accepted_until = NULL, closed_at = NULL, version = version + 1,
                updated_at = $2
             WHERE case_id = $1::text::uuid",
            &[&case_id, &now],
        )
        .await?;
        push_event(
            &tx,
            &case_id,
            now,
            None,
            "reopened",
            None,
            json!({ "reason": "accepted_risk_expired", "status": "open",
                    "previous_resolution": "accepted_risk" }),
        )
        .await?;
        audit(
            &tx,
            None,
            "case.reopen",
            &case_id,
            json!({ "number": number, "reason": "accepted_risk_expired" }),
        )
        .await?;
        tx.commit().await?;
        reopened += 1;
    }
    Ok(reopened)
}
