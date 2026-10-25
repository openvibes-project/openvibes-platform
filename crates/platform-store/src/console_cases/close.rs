//! Changing a case: its fields, closing it and reopening it by hand.

use chrono::{DateTime, Utc};
use deadpool_postgres::GenericClient;
use serde_json::json;

use super::{
    CaseChange, CaseDetail, Refusal, Viewer,
    events::{audit, push_event, username},
    is_uuid,
    list::assignee_available,
    note_ok, refuse, severity_ok, title_ok, unique_violation,
    visibility::{blocking_item, case_visible, item_visible, read_detail},
};
use crate::{Client, StoreError, console_read::AgentScope};

/// A case row as locked for a change.
pub(super) struct Locked {
    pub(super) number: i64,
    pub(super) title: String,
    pub(super) status: String,
    pub(super) severity: String,
    pub(super) assignee: Option<String>,
    pub(super) resolution: Option<String>,
    pub(super) resolution_note: Option<String>,
    pub(super) version: i64,
}

/// Locks the case if the viewer can see it.
pub(super) async fn lock_case(
    tx: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
) -> Result<Option<Locked>, StoreError> {
    if !is_uuid(case_id) {
        return Ok(None);
    }
    let visible = case_visible("c");
    let row = tx
        .query_opt(
            &format!(
                "SELECT c.number, c.title, c.status, c.severity, c.assignee_user_id::text,
                    c.resolution, c.resolution_note, c.version::bigint
                 FROM cases c WHERE c.case_id = $4::text::uuid AND {visible} FOR UPDATE OF c"
            ),
            viewer_params!(viewer, &case_id),
        )
        .await?;
    Ok(row.map(|row| Locked {
        number: row.get(0),
        title: row.get(1),
        status: row.get(2),
        severity: row.get(3),
        assignee: row.get(4),
        resolution: row.get(5),
        resolution_note: row.get(6),
        version: row.get(7),
    }))
}

/// Checks the closing note a request states for its new status: required
/// with `closed`, absent otherwise.
pub(super) fn closing_valid(change: &CaseChange<'_>) -> Result<(), (&'static str, &'static str)> {
    match (change.status == "closed", change.closing_note) {
        (false, Some(_)) => Err(("closing_note", "closing_note_not_allowed")),
        (true, None) => Err(("closing_note", "closing_note_required")),
        (true, Some(note)) if !note_ok(note) => Err(("closing_note", "invalid_note")),
        _ => Ok(()),
    }
}

/// Alarm, finding and vulnerability items that still stand in the way of
/// closing: without an outcome, resolved while the evidence is back, or
/// accepted risk whose date has passed ([`blocking_item`]).
/// Returns (visible, hidden) counts.
pub(super) async fn blocking_items(
    tx: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
) -> Result<(i64, i64), StoreError> {
    let (blocking, visible) = (blocking_item(), item_visible("i"));
    let rows = tx
        .query(
            &format!(
                "SELECT s.seen, count(*) FROM (
                    SELECT {visible} AS seen FROM case_items i
                    WHERE i.case_id = $4::text::uuid AND $3::text IS NOT NULL AND {blocking})
                 s GROUP BY s.seen"
            ),
            viewer_params!(viewer, &case_id),
        )
        .await?;
    let (mut seen, mut hidden) = (0, 0);
    for row in rows {
        if row.get::<_, bool>(0) {
            seen += row.get::<_, i64>(1);
        } else {
            hidden += row.get::<_, i64>(1);
        }
    }
    Ok((seen, hidden))
}

/// Looks for an exclusive item of the case that another open case holds.
pub(super) async fn reopen_conflict(
    tx: &impl GenericClient,
    viewer: &Viewer<'_>,
    case_id: &str,
) -> Result<Option<Option<i64>>, StoreError> {
    // The other case is named only if the caller can see it and the
    // clashing item.
    let visible = format!("{} AND {}", case_visible("oc"), item_visible("mine"));
    let row = tx
        .query_opt(
            &format!(
                "SELECT oc.number, {visible} FROM case_items mine
                 JOIN case_items o ON o.kind = mine.kind AND o.ref = mine.ref AND o.active
                      AND o.case_id <> mine.case_id
                 JOIN cases oc ON oc.case_id = o.case_id
                 WHERE mine.case_id = $4::text::uuid
                   AND mine.kind IN ('alarm', 'compliance_finding', 'vulnerability')
                 ORDER BY oc.number LIMIT 1"
            ),
            viewer_params!(viewer, &case_id),
        )
        .await?;
    Ok(row.map(|row| row.get::<_, bool>(1).then(|| row.get::<_, i64>(0))))
}

/// Changes a case's title, severity, status and assignee with a version
/// check. Closing needs a closing note and an outcome on every alarm,
/// finding and vulnerability, hidden ones included; it sets no resolution
/// (step 5d), and a case closed before keeps its own while it stays closed;
/// reopening needs that none of its items has joined another open case.
/// Sending the current values changes nothing and writes nothing.
pub async fn update(
    client: &mut Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
    change: &CaseChange<'_>,
    now: DateTime<Utc>,
) -> Result<Result<CaseDetail, Refusal>, StoreError> {
    if !title_ok(change.title) {
        return Ok(Err(Refusal::Invalid("title", "invalid_title")));
    }
    if !severity_ok(change.severity) {
        return Ok(Err(Refusal::Invalid("severity", "invalid_severity")));
    }
    if !matches!(change.status, "open" | "investigating" | "closed") {
        return Ok(Err(Refusal::Invalid("status", "invalid_status")));
    }
    if let Err((field, code)) = closing_valid(change) {
        return Ok(Err(Refusal::Invalid(field, code)));
    }
    let viewer = Viewer::new(scope, user_id);
    let tx = client.transaction().await?;
    let Some(current) = lock_case(&tx, &viewer, case_id).await? else {
        return refuse(tx, Refusal::NotFound).await;
    };
    if current.version != change.expected_version {
        return refuse(tx, Refusal::Stale).await;
    }
    let (was_closed, will_close) = (current.status == "closed", change.status == "closed");
    // Nothing else about how a closed case ended changes while it stays closed.
    if was_closed && will_close && current.resolution_note.as_deref() != change.closing_note {
        return refuse(tx, Refusal::Closed).await;
    }
    let assignee_changed = current.assignee.as_deref() != change.assignee_user_id;
    if assignee_changed
        && let Some(assignee) = change.assignee_user_id
        && !assignee_available(&tx, assignee).await?
    {
        return refuse(tx, Refusal::AssigneeUnavailable).await;
    }
    let fields_changed =
        current.title != change.title || current.severity != change.severity || assignee_changed;
    if !fields_changed && current.status == change.status {
        let Some(unchanged) = read_detail(&tx, &viewer, case_id).await? else {
            return Err(StoreError::Query);
        };
        tx.rollback().await?;
        return Ok(Ok(unchanged));
    }
    if !was_closed && will_close {
        let (seen, hidden) = blocking_items(&tx, &viewer, case_id).await?;
        if seen > 0 {
            return refuse(tx, Refusal::ItemsUnresolved(seen)).await;
        }
        if hidden > 0 {
            return refuse(tx, Refusal::HiddenItemsUnresolved).await;
        }
    }
    if was_closed
        && !will_close
        && let Some(number) = reopen_conflict(&tx, &viewer, case_id).await?
    {
        return refuse(tx, Refusal::ItemInCase(number)).await;
    }
    tx.execute(
        "UPDATE cases SET title = $2, severity = $3, status = $4,
            assignee_user_id = $5::text::uuid, resolution_note = $6,
            resolution = CASE WHEN $4 = 'closed' THEN resolution END,
            accepted_until = CASE WHEN $4 = 'closed' THEN accepted_until END,
            closed_at = CASE WHEN $4 = 'closed' THEN COALESCE(closed_at, $7) END,
            version = version + 1, updated_at = $7
         WHERE case_id = $1::text::uuid",
        &[
            &case_id,
            &change.title,
            &change.severity,
            &change.status,
            &change.assignee_user_id,
            &change.closing_note,
            &now,
        ],
    )
    .await?;
    if was_closed != will_close {
        let active = !will_close;
        let result = tx
            .execute(
                "UPDATE case_items SET active = $2 WHERE case_id = $1::text::uuid",
                &[&case_id, &active],
            )
            .await;
        match result {
            Ok(_) => {}
            // Another request put one of the items in a new open case.
            Err(error) if unique_violation(&error) => {
                return refuse(tx, Refusal::ItemInCase(None)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    if assignee_changed {
        let (from, to) = (
            username(&tx, current.assignee.as_deref()).await?,
            username(&tx, change.assignee_user_id).await?,
        );
        push_event(
            &tx,
            case_id,
            now,
            Some(user_id),
            "assigned",
            None,
            json!({ "from": from, "to": to }),
        )
        .await?;
    }
    if current.severity != change.severity {
        push_event(
            &tx,
            case_id,
            now,
            Some(user_id),
            "severity",
            None,
            json!({ "from": current.severity, "to": change.severity }),
        )
        .await?;
    }
    if will_close && !was_closed {
        push_event(
            &tx,
            case_id,
            now,
            Some(user_id),
            "resolved",
            change.closing_note,
            json!({}),
        )
        .await?;
        audit(
            &tx,
            Some(user_id),
            "case.close",
            case_id,
            json!({ "number": current.number }),
        )
        .await?;
    } else if was_closed && !will_close {
        push_event(
            &tx,
            case_id,
            now,
            Some(user_id),
            "reopened",
            None,
            json!({ "reason": "manual", "status": change.status,
                    "previous_resolution": current.resolution }),
        )
        .await?;
        audit(
            &tx,
            Some(user_id),
            "case.reopen",
            case_id,
            json!({ "number": current.number, "reason": "manual" }),
        )
        .await?;
    } else if current.status != change.status {
        push_event(
            &tx,
            case_id,
            now,
            Some(user_id),
            "status",
            None,
            json!({ "from": current.status, "to": change.status }),
        )
        .await?;
    }
    if fields_changed || (current.status != change.status && !was_closed && !will_close) {
        audit(
            &tx,
            Some(user_id),
            "case.update",
            case_id,
            json!({ "number": current.number, "title": change.title,
                    "severity": change.severity, "status": change.status,
                    "assigned": assignee_changed }),
        )
        .await?;
    }
    let Some(saved) = read_detail(&tx, &viewer, case_id).await? else {
        return Err(StoreError::Query);
    };
    tx.commit().await?;
    Ok(Ok(saved))
}
