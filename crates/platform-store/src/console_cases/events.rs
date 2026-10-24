//! The timeline and the audit log: entries, notes and the user names they show.

use chrono::{DateTime, Utc};
use deadpool_postgres::GenericClient;
use serde_json::{Value, json};

use super::{
    CaseEvent, MAX_EVENTS_PER_CASE, Refusal, Viewer, close::lock_case, note_ok, refuse,
    visibility::read_events,
};
use crate::{Client, StoreError, console_read::AgentScope};

pub(super) async fn audit(
    tx: &impl GenericClient,
    actor: Option<&str>,
    action: &str,
    case_id: &str,
    detail: Value,
) -> Result<(), StoreError> {
    match actor {
        Some(user_id) => {
            tx.execute(
                "INSERT INTO audit_log (actor, action, target, result, detail,
                     actor_kind, actor_id, actor_display, target_kind, target_id)
                 SELECT $1, $2, $3, 'success', $4, 'user', $1, u.display_name, 'case', $3
                 FROM console_users u WHERE u.user_id = $1::text::uuid",
                &[&user_id, &action, &case_id, &detail],
            )
            .await?;
        }
        None => {
            tx.execute(
                "INSERT INTO audit_log (actor, action, target, result, detail,
                     actor_kind, actor_display, target_kind, target_id)
                 VALUES ('system', $1, $2, 'success', $3, 'system', 'system', 'case', $2)",
                &[&action, &case_id, &detail],
            )
            .await?;
        }
    }
    Ok(())
}

pub(super) async fn push_event(
    tx: &impl GenericClient,
    case_id: &str,
    at: DateTime<Utc>,
    actor: Option<&str>,
    kind: &str,
    body: Option<&str>,
    detail: Value,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO case_events (case_id, at, actor_user_id, kind, body, detail)
         VALUES ($1::text::uuid, $2, $3::text::uuid, $4, $5, $6)",
        &[&case_id, &at, &actor, &kind, &body, &detail],
    )
    .await?;
    Ok(())
}

pub(super) async fn touch(
    tx: &impl GenericClient,
    case_id: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    tx.execute(
        "UPDATE cases SET updated_at = GREATEST(updated_at, $2) WHERE case_id = $1::text::uuid",
        &[&case_id, &now],
    )
    .await?;
    Ok(())
}

pub(super) async fn username(
    db: &impl GenericClient,
    user_id: Option<&str>,
) -> Result<Value, StoreError> {
    let Some(user_id) = user_id else {
        return Ok(Value::Null);
    };
    Ok(db
        .query_opt(
            "SELECT username FROM console_users WHERE user_id = $1::text::uuid",
            &[&user_id],
        )
        .await?
        .map_or(Value::Null, |row| json!(row.get::<_, String>(0))))
}

/// Appends a note to the timeline. Notes can be added to a closed case.
pub async fn add_note(
    client: &mut Client,
    scope: &AgentScope,
    user_id: &str,
    case_id: &str,
    text: &str,
    now: DateTime<Utc>,
) -> Result<Result<CaseEvent, Refusal>, StoreError> {
    if !note_ok(text) {
        return Ok(Err(Refusal::Invalid("body", "invalid_note")));
    }
    let viewer = Viewer::new(scope, user_id);
    let tx = client.transaction().await?;
    let Some(current) = lock_case(&tx, &viewer, case_id).await? else {
        return refuse(tx, Refusal::NotFound).await;
    };
    let events: i64 = tx
        .query_one(
            "SELECT count(*) FROM case_events WHERE case_id = $1::text::uuid",
            &[&case_id],
        )
        .await?
        .get(0);
    if events >= MAX_EVENTS_PER_CASE {
        return refuse(tx, Refusal::TimelineFull).await;
    }
    let row = tx
        .query_one(
            "INSERT INTO case_events (case_id, at, actor_user_id, kind, body, detail)
             VALUES ($1::text::uuid, $2, $3::text::uuid, 'note', $4, '{}')
             RETURNING event_id",
            &[&case_id, &now, &user_id, &text],
        )
        .await?;
    let event_id: i64 = row.get(0);
    touch(&tx, case_id, now).await?;
    // Never the text: the audit log is read by more people than the case.
    audit(
        &tx,
        Some(user_id),
        "case.note",
        case_id,
        json!({ "number": current.number, "event_id": event_id, "length": text.chars().count() }),
    )
    .await?;
    let events = read_events(&tx, &viewer, case_id).await?;
    let Some(event) = events.into_iter().find(|event| event.event_id == event_id) else {
        return Err(StoreError::Query);
    };
    tx.commit().await?;
    Ok(Ok(event))
}
