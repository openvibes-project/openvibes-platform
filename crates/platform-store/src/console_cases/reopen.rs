//! The lazy reopen checks, run as the platform.

use chrono::{DateTime, Utc};
use serde_json::json;

use super::{
    EVIDENCE_WATCH_DAYS, REOPEN_BATCH,
    events::{audit, push_event, touch},
    unique_violation,
    visibility::item_gone,
};
use crate::{Client, StoreError};

/// What reopens a closed case because of some of its items, which lose
/// their outcome so that someone decides again.
struct Trigger {
    /// Why, on the timeline and in the audit row.
    reason: &'static str,
    /// A condition on the closed case `c`; `$1` is [`Trigger::at`].
    case: &'static str,
    /// A condition on the item `i`; `$1` is [`Trigger::at`].
    item: String,
    /// The time the conditions compare with.
    at: DateTime<Utc>,
    /// The time of the reopen.
    now: DateTime<Utc>,
}

/// Reopens recently closed cases whose `resolved` evidence has come back,
/// as the platform (audit actor `system`).
///
/// Only cases closed within [`EVIDENCE_WATCH_DAYS`] are looked at, which
/// keeps the check bounded, and only items with the outcome `resolved`:
/// the other outcomes are decisions, not evidence (accepted risk reopens on
/// its date, see [`reopen_due`]). Each returning item loses its outcome, so
/// someone decides again; the other outcomes stay. A case with an item that
/// has since joined another open case is left closed. The timeline gets one
/// `reopened` entry that names no item, and an `item_outcome` entry per
/// returning item, which, like every item entry, only those who can see the
/// item are shown. Returns how many reopened.
pub async fn reopen_evidence_returned(
    client: &mut Client,
    now: DateTime<Utc>,
) -> Result<u32, StoreError> {
    let gone = item_gone();
    reopen_on_items(
        client,
        Trigger {
            reason: "evidence_returned",
            case: "c.closed_at >= $1",
            item: format!(
                "i.outcome = 'resolved'
                 AND i.kind IN ('alarm', 'compliance_finding', 'vulnerability') AND NOT ({gone})"
            ),
            at: now - chrono::Duration::days(EVIDENCE_WATCH_DAYS),
            now,
        },
    )
    .await
}

/// Reopens closed cases with an item whose accepted risk ran out
/// (`outcome_until`, step 5d), as the platform, the way
/// [`reopen_evidence_returned`] does: only those items lose their outcome.
async fn reopen_item_acceptance_expired(
    client: &mut Client,
    now: DateTime<Utc>,
) -> Result<u32, StoreError> {
    reopen_on_items(
        client,
        Trigger {
            reason: "accepted_risk_expired",
            case: "true",
            item: "i.outcome = 'accepted_risk' AND i.outcome_until <= $1".to_owned(),
            at: now,
            now,
        },
    )
    .await
}

/// A closed case `c` one of whose exclusive items another open case holds:
/// it stays closed, and the checks skip it so that it cannot fill a batch.
const TAKEN: &str = "SELECT 1 FROM case_items mine
    JOIN case_items o ON o.kind = mine.kind AND o.ref = mine.ref AND o.active
         AND o.case_id <> mine.case_id
    WHERE mine.case_id = c.case_id
      AND mine.kind IN ('alarm', 'compliance_finding', 'vulnerability')";

/// Reopens up to [`REOPEN_BATCH`] closed cases that `trigger` names.
async fn reopen_on_items(client: &mut Client, trigger: Trigger) -> Result<u32, StoreError> {
    let Trigger {
        reason,
        case,
        item,
        at,
        now,
    } = trigger;
    let due = client
        .query(
            &format!(
                "SELECT c.case_id::text FROM cases c
                 WHERE c.status = 'closed' AND {case}
                   AND EXISTS (SELECT 1 FROM case_items i WHERE i.case_id = c.case_id AND {item})
                   AND NOT EXISTS ({TAKEN})
                 ORDER BY c.closed_at DESC LIMIT $2"
            ),
            &[&at, &REOPEN_BATCH],
        )
        .await?;
    let mut reopened = 0;
    for row in due {
        let case_id: String = row.get(0);
        let tx = client.transaction().await?;
        // Both conditions in each query, so that `$1` is always typed.
        let locked = tx
            .query_opt(
                &format!(
                    "SELECT c.number, c.resolution FROM cases c
                     WHERE c.case_id = $2::text::uuid AND c.status = 'closed' AND {case}
                       AND EXISTS (SELECT 1 FROM case_items i
                                   WHERE i.case_id = c.case_id AND {item})
                       AND NOT EXISTS ({TAKEN})
                     FOR UPDATE OF c SKIP LOCKED"
                ),
                &[&at, &case_id],
            )
            .await?;
        let Some(locked) = locked else {
            tx.rollback().await?;
            continue;
        };
        let (number, previous): (i64, Option<String>) = (locked.get(0), locked.get(1));
        let items = tx
            .query(
                &format!(
                    "SELECT i.item_id::text, i.kind, i.ref, i.agent_id, i.outcome
                     FROM case_items i JOIN cases c ON c.case_id = i.case_id
                     WHERE i.case_id = $2::text::uuid AND {case} AND {item}
                     ORDER BY i.seq"
                ),
                &[&at, &case_id],
            )
            .await?;
        let ids: Vec<String> = items.iter().map(|item| item.get(0)).collect();
        let activated = tx
            .execute(
                "UPDATE case_items SET active = true,
                    outcome = CASE WHEN item_id::text = ANY($2) THEN NULL ELSE outcome END,
                    outcome_note = CASE WHEN item_id::text = ANY($2) THEN NULL
                                        ELSE outcome_note END,
                    outcome_until = CASE WHEN item_id::text = ANY($2) THEN NULL
                                         ELSE outcome_until END
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
            json!({ "reason": reason, "status": "open", "previous_resolution": previous }),
        )
        .await?;
        let mut named = Vec::with_capacity(items.len());
        for item in &items {
            let (item_id, kind, reference, agent_id, from): (
                String,
                String,
                String,
                Option<String>,
                Option<String>,
            ) = (
                item.get(0),
                item.get(1),
                item.get(2),
                item.get(3),
                item.get(4),
            );
            push_event(
                &tx,
                &case_id,
                now,
                None,
                "item_outcome",
                None,
                json!({ "item_id": item_id, "item_kind": kind, "item_ref": reference,
                        "item_agent_id": agent_id, "from": from, "to": null,
                        "reason": reason }),
            )
            .await?;
            named.push(json!({ "kind": kind, "ref": reference }));
        }
        audit(
            &tx,
            None,
            "case.reopen",
            &case_id,
            json!({ "number": number, "reason": reason, "items": named }),
        )
        .await?;
        tx.commit().await?;
        reopened += 1;
    }
    Ok(reopened)
}

/// The lazy reopen checks, for the console to run before it lists or reads
/// cases: accepted risk that has run out (the case's, then each item's),
/// and evidence that has returned.
pub async fn reopen_due(client: &mut Client, now: DateTime<Utc>) -> Result<u32, StoreError> {
    let reopened = reopen_expired(client, now).await?
        + reopen_item_acceptance_expired(client, now).await?
        + reopen_evidence_returned(client, now).await?;
    clear_open_acceptances_expired(client, now).await?;
    Ok(reopened)
}

/// Clears the accepted risk that ran out on items of cases that are not
/// closed, as the platform: the item needs a decision again, so the case is
/// no longer ready to close. The case's status stays; each item gets an
/// `item_outcome` entry (reason `accepted_risk_expired`).
async fn clear_open_acceptances_expired(
    client: &mut Client,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let due = client
        .query(
            "SELECT c.case_id::text FROM cases c JOIN case_items i ON i.case_id = c.case_id
             WHERE c.status <> 'closed' AND i.outcome = 'accepted_risk' AND i.outcome_until <= $1
             GROUP BY c.case_id ORDER BY min(i.outcome_until) LIMIT $2",
            &[&now, &REOPEN_BATCH],
        )
        .await?;
    for row in due {
        let case_id: String = row.get(0);
        let tx = client.transaction().await?;
        // The case first, as every change locks it, so a close cannot race.
        let locked = tx
            .query_opt(
                "SELECT number FROM cases
                 WHERE case_id = $1::text::uuid AND status <> 'closed'
                 FOR UPDATE SKIP LOCKED",
                &[&case_id],
            )
            .await?;
        let Some(locked) = locked else {
            tx.rollback().await?;
            continue;
        };
        let number: i64 = locked.get(0);
        let items = tx
            .query(
                "UPDATE case_items SET outcome = NULL, outcome_note = NULL, outcome_until = NULL
                 WHERE case_id = $1::text::uuid AND outcome = 'accepted_risk'
                   AND outcome_until <= $2
                 RETURNING item_id::text, kind, ref, agent_id",
                &[&case_id, &now],
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
                        "item_agent_id": agent_id, "from": "accepted_risk", "to": null,
                        "reason": "accepted_risk_expired" }),
            )
            .await?;
            named.push(json!({ "kind": kind, "ref": reference }));
        }
        touch(&tx, &case_id, now).await?;
        audit(
            &tx,
            None,
            "case.item.outcome",
            &case_id,
            json!({ "number": number, "reason": "accepted_risk_expired", "items": named }),
        )
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

/// Reopens cases closed as accepted risk before step 5d whose case-level
/// `accepted_until` has run out, as the platform (audit actor `system`).
/// Its accepted-risk items lose that outcome, so someone decides again. A case with an item that has since
/// joined another open case is left closed. Returns how many reopened.
pub async fn reopen_expired(client: &mut Client, now: DateTime<Utc>) -> Result<u32, StoreError> {
    let due = client
        .query(
            &format!(
                "SELECT c.case_id::text FROM cases c
                 WHERE c.status = 'closed' AND c.resolution = 'accepted_risk'
                   AND c.accepted_until <= $1 AND NOT EXISTS ({TAKEN})
                 ORDER BY c.accepted_until LIMIT $2"
            ),
            &[&now, &REOPEN_BATCH],
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
                    outcome_note = CASE WHEN outcome = 'accepted_risk' THEN NULL ELSE outcome_note END,
                    outcome_until = CASE WHEN outcome = 'accepted_risk' THEN NULL ELSE outcome_until END
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
