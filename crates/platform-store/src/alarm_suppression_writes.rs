//! Suppression writes (roles spec §8): request, decide, withdraw and
//! remove, each in one transaction with its audit line. Types and reads
//! live in `alarm_suppressions.rs`.

use chrono::{DateTime, NaiveDate, Utc};

use crate::{
    Client, StoreError,
    alarm_suppressions::{
        Change, Request, State, What, Where, audit, fetch, in_reach, params, valid_reason,
    },
    alarms,
    console_read::{AgentScope, agent_visibility},
    console_settings,
};

/// Requests a suppression derived from alarm `req.alarm_row_id`, which must
/// be within `suppress` (the caller's `alarms.suppress` reach), as must the
/// where. With `suppressions.require_approval` on it waits; otherwise it is
/// active at once and closes its source alarm (ruling 3).
pub async fn request(
    client: &mut Client,
    suppress: &AgentScope,
    req: &Request<'_>,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Change, StoreError> {
    let reason = req.reason.trim();
    if !valid_reason(reason) {
        return Ok(Change::Invalid("reason".into()));
    }
    if !matches!(req.for_days, None | Some(7 | 30)) {
        return Ok(Change::Invalid("for".into()));
    }
    let (global, groups) = params(suppress);
    match &req.place {
        Where::All if !global => return Ok(Change::NeedsGlobalScope),
        Where::Group(group) if !global && !groups.contains(group) => {
            return Ok(Change::NotInReach);
        }
        _ => {}
    }
    let tx = client.transaction().await?;
    let group = match &req.place {
        Where::Group(group) => Some(group),
        _ => None,
    };
    if let Some(group) = group {
        let known = tx
            .query_opt(
                "SELECT 1 FROM console_asset_groups WHERE asset_group_id::text = $1",
                &[group],
            )
            .await?;
        if known.is_none() {
            return Ok(Change::Invalid("group".into()));
        }
    }
    let agent = agent_visibility("a.agent_id", "$1", "$2");
    let Some(alarm) = tx
        .query_opt(
            &format!(
                "SELECT al.rule_set_id, al.rule_id, al.agent_id, al.process->>'exe',
                    al.process->'args'
                 FROM alarms al JOIN agents a ON a.agent_id = al.agent_id
                 WHERE al.id = $3 AND {agent}"
            ),
            &[&global, &groups, &req.alarm_row_id],
        )
        .await?
    else {
        return Ok(Change::NotFound);
    };
    let (scope, hash) = match req.what {
        What::Program => ("program", None),
        What::Command => {
            // Args that do not parse would hash as `[]` and quiet another command.
            let args = alarm.get::<_, serde_json::Value>(4);
            let Ok(args) = serde_json::from_value::<Vec<String>>(args) else {
                return Ok(Change::Invalid("command".into()));
            };
            ("command", Some(alarms::args_sha256(&args)))
        }
    };
    let agent_id = matches!(req.place, Where::Host).then(|| alarm.get::<_, String>(2));
    let state = if console_settings::require_approval(&tx).await? {
        State::Waiting
    } else {
        State::Active
    };
    let activated_at = (state == State::Active).then_some(now);
    let id: i64 = tx
        .query_one(
            "INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, agent_id, host_group_id,
                exe, args_sha256, note, created_by, created_at, state, for_days, activated_at,
                expires_at, alarm_id)
             VALUES ($1, $2, $3, $4, $5::text::uuid, $6, $7, $8, $9, $10, $11, $12, $13,
                $13::timestamptz + make_interval(hours => 24 * $12::int), $14)
             RETURNING id",
            &[
                &alarm.get::<_, String>(0),
                &alarm.get::<_, String>(1),
                &scope,
                &agent_id,
                &group,
                &alarm.get::<_, Option<String>>(3),
                &hash,
                &reason,
                &actor,
                &now,
                &state.as_str(),
                &req.for_days,
                &activated_at,
                &req.alarm_row_id,
            ],
        )
        .await?
        .get(0);
    let action = if state == State::Active {
        close_source(&tx, id, req.alarm_row_id, actor, now).await?;
        "alarm.suppression.created"
    } else {
        "alarm.suppression.requested"
    };
    let made = fetch(&tx, id, now).await?;
    audit(&tx, actor, action, &made).await?;
    tx.commit().await?;
    Ok(Change::Done(made))
}

/// Approves or rejects waiting suppression `id`, which must be within
/// `approve` (the caller's `alarms.suppressions.approve` reach). The
/// requester may not decide their own; rejecting needs a reason.
/// Approving starts the For period and closes the source alarm.
pub async fn decide(
    client: &mut Client,
    approve: &AgentScope,
    id: i64,
    approve_it: bool,
    reason: Option<&str>,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Change, StoreError> {
    let (global, groups) = params(approve);
    let tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt(
            &format!(
                "SELECT s.state, s.created_by, s.alarm_id,
                    s.host_group_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM console_asset_groups g
                        WHERE g.asset_group_id = s.host_group_id)
                 FROM alarm_suppressions s
                 WHERE s.id = $3 AND {} FOR UPDATE OF s",
                in_reach(false)
            ),
            &[&global, &groups, &id],
        )
        .await?
    else {
        return Ok(Change::NotFound);
    };
    if row.get::<_, &str>(0) != "waiting" {
        return Ok(Change::WrongState);
    }
    if row.get::<_, &str>(1) == actor {
        return Ok(Change::OwnRequest);
    }
    let reason = reason.map(str::trim).filter(|reason| !reason.is_empty());
    if reason.is_some_and(|reason| !valid_reason(reason)) || (!approve_it && reason.is_none()) {
        return Ok(Change::Invalid("reason".into()));
    }
    // A deleted group's suppression would match nothing (ruling 4).
    if approve_it && row.get::<_, bool>(3) {
        return Ok(Change::Invalid("group".into()));
    }
    let (state, action) = if approve_it {
        (State::Active, "alarm.suppression.approved")
    } else {
        (State::Rejected, "alarm.suppression.rejected")
    };
    tx.execute(
        "UPDATE alarm_suppressions SET state = $2, decided_by = $3, decided_at = $4,
            decision_reason = $5,
            activated_at = CASE WHEN $2 = 'active' THEN $4::timestamptz END,
            expires_at = CASE WHEN $2 = 'active' THEN $4::timestamptz + make_interval(hours => 24 * for_days) END
         WHERE id = $1",
        &[&id, &state.as_str(), &actor, &now, &reason],
    )
    .await?;
    if let (true, Some(alarm)) = (approve_it, row.get::<_, Option<i64>>(2)) {
        close_source(&tx, id, alarm, actor, now).await?;
    }
    let decided = fetch(&tx, id, now).await?;
    audit(&tx, actor, action, &decided).await?;
    tx.commit().await?;
    Ok(Change::Done(decided))
}

/// Withdraws the caller's own waiting request `id`; another person's is
/// [`Change::NotFound`].
pub async fn withdraw(
    client: &mut Client,
    id: i64,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Change, StoreError> {
    let tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt(
            "SELECT state FROM alarm_suppressions WHERE id = $1 AND created_by = $2 FOR UPDATE",
            &[&id, &actor],
        )
        .await?
    else {
        return Ok(Change::NotFound);
    };
    if row.get::<_, &str>(0) != "waiting" {
        return Ok(Change::WrongState);
    }
    tx.execute(
        "UPDATE alarm_suppressions SET state = 'withdrawn', decided_by = $2, decided_at = $3
         WHERE id = $1",
        &[&id, &actor, &now],
    )
    .await?;
    let withdrawn = fetch(&tx, id, now).await?;
    audit(&tx, actor, "alarm.suppression.withdrawn", &withdrawn).await?;
    tx.commit().await?;
    Ok(Change::Done(withdrawn))
}

/// Removes active suppression `id` if it is within `suppress` (ruling 6);
/// the row stays, with `removed_at` set.
pub async fn remove(
    client: &mut Client,
    suppress: &AgentScope,
    id: i64,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Change, StoreError> {
    let (global, groups) = params(suppress);
    let tx = client.transaction().await?;
    let found = tx
        .query_opt(
            &format!(
                "SELECT 1 FROM alarm_suppressions s
                 WHERE s.id = $3 AND s.state = 'active' AND {} FOR UPDATE OF s",
                in_reach(false)
            ),
            &[&global, &groups, &id],
        )
        .await?;
    if found.is_none() {
        return Ok(Change::NotFound);
    }
    tx.execute(
        "UPDATE alarm_suppressions SET state = 'removed', removed_at = $2, removed_by = $3
         WHERE id = $1",
        &[&id, &now, &actor],
    )
    .await?;
    let removed = fetch(&tx, id, now).await?;
    audit(&tx, actor, "alarm.suppression.removed", &removed).await?;
    tx.commit().await?;
    Ok(Change::Done(removed))
}

/// Closes source alarm `alarm_row_id` as ingest closes a matched one, if
/// it is still open or investigating: false positive, suppressed by `id`,
/// with a triage history line.
async fn close_source(
    tx: &deadpool_postgres::Transaction<'_>,
    id: i64,
    alarm_row_id: i64,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let note = format!("suppressed by #{id}");
    let Some(row) = tx
        .query_opt(
            "WITH old AS (
                SELECT id, first_seen_day, state FROM alarms
                WHERE id = $1 AND state IN ('open', 'investigating') FOR UPDATE)
             UPDATE alarms al SET state = 'false_positive', suppressed_by = $2, note = $3,
                triage_updated_at = $4, triage_updated_by = $5,
                triage_version = al.triage_version + 1
             FROM old WHERE al.id = old.id AND al.first_seen_day = old.first_seen_day
             RETURNING old.first_seen_day, old.state",
            &[&alarm_row_id, &id, &note, &now, &actor],
        )
        .await?
    else {
        return Ok(());
    };
    let (day, from): (NaiveDate, String) = (row.get(0), row.get(1));
    alarms::history(
        tx,
        alarm_row_id,
        day,
        Some(&from),
        "false_positive",
        &note,
        now,
        actor,
    )
    .await
}
