//! Suppression writes (roles spec §8): request, decide, withdraw and
//! remove, each in one transaction with its audit line, and [`facts`],
//! what the console shows beside a row it lists or writes. Types and
//! reads live in `alarm_suppressions.rs`.

use std::collections::HashMap;

use chrono::{DateTime, NaiveDate, Utc};
use deadpool_postgres::GenericClient;

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
        let reach = (global, groups);
        close_source(&tx, id, &[req.alarm_row_id], reach, actor, now).await?;
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
                in_reach(false, "$1", "$2")
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
        // The requester reached the source alarm; the where still must cover it.
        close_source(&tx, id, &[alarm], (true, Vec::new()), actor, now).await?;
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
                in_reach(false, "$1", "$2")
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

/// Closes, after [`request`] made suppression `id` active, the other
/// selected alarms `alarm_ids` it covers (bulk suppress); each must be
/// within `suppress`. Returns those of `alarm_ids` now closed by `id`.
pub async fn close_covered(
    client: &mut Client,
    suppress: &AgentScope,
    id: i64,
    alarm_ids: &[i64],
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Vec<i64>, StoreError> {
    let tx = client.transaction().await?;
    close_source(&tx, id, alarm_ids, params(suppress), actor, now).await?;
    let closed = tx
        .query(
            "SELECT id FROM alarms WHERE id = ANY($1) AND suppressed_by = $2",
            &[&alarm_ids, &id],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect();
    tx.commit().await?;
    Ok(closed)
}

/// Closes alarms `alarm_row_ids` as ingest closes a matched one, if
/// active suppression `id` covers them (rule, program, command, host or
/// group), they are within `reach` (as [`params`] gives it) and still open
/// or investigating: false positive, suppressed by `id`, with a triage
/// history line.
async fn close_source(
    tx: &deadpool_postgres::Transaction<'_>,
    id: i64,
    alarm_row_ids: &[i64],
    (global, groups): (bool, Vec<String>),
    actor: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let note = format!("suppressed by #{id}");
    let rows = tx
        .query(
            &format!(
                "WITH old AS (
                    SELECT al.id, al.first_seen_day, al.state FROM alarms al
                    JOIN agents a ON a.agent_id = al.agent_id
                    JOIN alarm_suppressions s ON s.id = $2 AND s.state = 'active'
                    WHERE al.id = ANY($1) AND al.state IN ('open', 'investigating')
                      AND al.rule_set_id = s.rule_set_id AND al.rule_id = s.rule_id
                      AND al.process->>'exe' IS NOT DISTINCT FROM s.exe
                      AND (s.scope = 'program' OR al.id = s.alarm_id)
                      AND (s.agent_id IS NULL OR al.agent_id = s.agent_id)
                      AND (s.host_group_id IS NULL
                           OR console_host_in_group(al.agent_id, s.host_group_id))
                      AND {}
                    FOR UPDATE OF al)
                 UPDATE alarms al SET state = 'false_positive', suppressed_by = $2, note = $3,
                    triage_updated_at = $4, triage_updated_by = $5,
                    triage_version = al.triage_version + 1
                 FROM old WHERE al.id = old.id AND al.first_seen_day = old.first_seen_day
                 RETURNING al.id, old.first_seen_day, old.state",
                agent_visibility("al.agent_id", "$6", "$7")
            ),
            &[&alarm_row_ids, &id, &note, &now, &actor, &global, &groups],
        )
        .await?;
    for row in rows {
        let (alarm, day, from): (i64, NaiveDate, String) = (row.get(0), row.get(1), row.get(2));
        alarms::history(
            tx,
            alarm,
            day,
            Some(&from),
            "false_positive",
            &note,
            now,
            actor,
        )
        .await?;
    }
    Ok(())
}

/// What the console shows beside one suppression for one caller.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Facts {
    /// The host's name, for a row on one host.
    pub hostname: Option<String>,
    /// The requester's display name (the stored id when not a person).
    pub requested_by: String,
    /// The decider's display name, likewise.
    pub decided_by: Option<String>,
    /// Within the caller's `alarms.suppressions.approve` reach, and its
    /// group (if any) still exists.
    pub approvable: bool,
    /// Within the caller's `alarms.suppress` reach (ruling 6).
    pub removable: bool,
}

/// [`Facts`] of suppressions `ids` for a caller whose approve and
/// suppress reaches are `approve` and `suppress` (`None` when not held),
/// with the predicate [`decide`] and [`remove`] use.
pub async fn facts(
    client: &impl GenericClient,
    ids: &[i64],
    approve: Option<&AgentScope>,
    suppress: Option<&AgentScope>,
) -> Result<HashMap<i64, Facts>, StoreError> {
    let none = (false, Vec::new());
    let (approve_all, approve_groups) = approve.map_or_else(|| none.clone(), params);
    let (suppress_all, suppress_groups) = suppress.map_or(none, params);
    let query = format!(
        "SELECT s.id, h.hostname,
            COALESCE(NULLIF(ru.display_name, ''), ru.username, s.created_by),
            COALESCE(NULLIF(du.display_name, ''), du.username, s.decided_by),
            {} AND (s.host_group_id IS NULL OR EXISTS (SELECT 1 FROM console_asset_groups g
                WHERE g.asset_group_id = s.host_group_id)), {}
         FROM alarm_suppressions s
         LEFT JOIN agents h ON h.agent_id = s.agent_id
         LEFT JOIN console_users ru ON ru.user_id::text = s.created_by
         LEFT JOIN console_users du ON du.user_id::text = s.decided_by
         WHERE s.id = ANY($1)",
        in_reach(false, "$2", "$3"),
        in_reach(false, "$4", "$5")
    );
    let rows = client
        .query(
            &query,
            &[
                &ids,
                &approve_all,
                &approve_groups,
                &suppress_all,
                &suppress_groups,
            ],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| {
            let facts = Facts {
                hostname: row.get(1),
                requested_by: row.get(2),
                decided_by: row.get(3),
                approvable: row.get(4),
                removable: row.get(5),
            };
            (row.get(0), facts)
        })
        .collect())
}
