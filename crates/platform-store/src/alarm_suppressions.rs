//! Alarm suppressions (P14) as the console manages them. A suppression is
//! always derived from an alarm the caller can see, never typed in. `host`
//! applies to that alarm's agent; `program` and `command` apply on every
//! host, so only a caller with global scope may create, see or remove them.
//! Removing one keeps the row (`removed_at`) as history.

use chrono::{DateTime, Utc};

use crate::{
    Client, StoreError, alarms,
    console_read::{AgentScope, agent_visibility},
};

/// One active suppression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Suppression {
    /// Its id (alarms name it in "suppressed by #id").
    pub id: i64,
    /// Rule set of the rule.
    pub rule_set_id: String,
    /// Rule it quiets.
    pub rule_id: String,
    /// `host`, `program` or `command`.
    pub scope: String,
    /// The agent, for `host`.
    pub agent_id: Option<String>,
    /// The program, for `program` and `command`.
    pub exe: Option<String>,
    /// SHA-256 of the masked args' JSON array, for `command`.
    pub args_sha256: Option<String>,
    /// Why.
    pub note: String,
    /// Who created it.
    pub created_by: String,
    /// When.
    pub created_at: DateTime<Utc>,
}

/// Outcome of a create or a remove.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // one per request; boxing buys nothing
pub enum Change {
    /// Done; the suppression as it now is.
    Done(Suppression),
    /// The alarm or suppression is absent or outside the caller's scope.
    NotFound,
    /// `program`/`command` need a caller with global scope.
    NeedsGlobalScope,
    /// Unknown scope, or a note that is empty or over 4,000 characters.
    Invalid,
}

const COLUMNS: &str = "s.id, s.rule_set_id, s.rule_id, s.scope, s.agent_id, s.exe,
    s.args_sha256, s.note, s.created_by, s.created_at";

fn suppression(row: &tokio_postgres::Row) -> Suppression {
    Suppression {
        id: row.get(0),
        rule_set_id: row.get(1),
        rule_id: row.get(2),
        scope: row.get(3),
        agent_id: row.get(4),
        exe: row.get(5),
        args_sha256: row.get(6),
        note: row.get(7),
        created_by: row.get(8),
        created_at: row.get(9),
    }
}

fn params(scope: &AgentScope) -> (bool, Vec<String>) {
    match scope {
        AgentScope::Global => (true, Vec::new()),
        AgentScope::AssetGroups(groups) => (false, groups.clone()),
    }
}

/// Visible means: a `host` suppression on an agent in scope, or any
/// suppression for a global caller.
fn visible_sql() -> String {
    let agent = agent_visibility("a.agent_id", "$1", "$2");
    format!(
        "($1 OR (s.scope = 'host' AND EXISTS (
            SELECT 1 FROM agents a WHERE a.agent_id = s.agent_id AND {agent})))"
    )
}

/// Active suppressions the caller may see, newest first.
pub async fn list(client: &Client, scope: &AgentScope) -> Result<Vec<Suppression>, StoreError> {
    let (global, groups) = params(scope);
    let query = format!(
        "SELECT {COLUMNS} FROM alarm_suppressions s
         WHERE s.removed_at IS NULL AND {} ORDER BY s.id DESC",
        visible_sql()
    );
    Ok(client
        .query(&query, &[&global, &groups])
        .await?
        .iter()
        .map(suppression)
        .collect())
}

fn audit_detail(suppression: &Suppression) -> serde_json::Value {
    serde_json::json!({
        "rule_set_id": suppression.rule_set_id,
        "rule_id": suppression.rule_id,
        "scope": suppression.scope,
        "agent_id": suppression.agent_id,
        "exe": suppression.exe,
    })
}

async fn audit(
    tx: &deadpool_postgres::Transaction<'_>,
    actor: &str,
    action: &str,
    suppression: &Suppression,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO audit_log (actor, action, target, result, detail, actor_kind, actor_id,
            actor_display, target_kind, target_id)
         VALUES ($1, $2, 'alarm_suppression', 'success', $3, 'user', $1, $1,
            'alarm_suppression', $4)",
        &[
            &actor,
            &action,
            &audit_detail(suppression),
            &suppression.id.to_string(),
        ],
    )
    .await?;
    Ok(())
}

/// Creates a suppression derived from alarm `alarm_row_id` (the platform's
/// id) with scope `kind`. It applies to alarms stored from now on; past
/// alarms keep their triage.
pub async fn create(
    client: &mut Client,
    scope: &AgentScope,
    alarm_row_id: i64,
    kind: &str,
    note: &str,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Change, StoreError> {
    if !matches!(kind, "host" | "program" | "command")
        || note.trim().is_empty()
        || note.chars().count() > 4000
    {
        return Ok(Change::Invalid);
    }
    if kind != "host" && !matches!(scope, AgentScope::Global) {
        return Ok(Change::NeedsGlobalScope);
    }
    let (global, groups) = params(scope);
    let agent = agent_visibility("a.agent_id", "$1", "$2");
    let tx = client.transaction().await?;
    let Some(alarm) = tx
        .query_opt(
            &format!(
                "SELECT al.rule_set_id, al.rule_id, al.agent_id, al.process->>'exe',
                    al.process->'args'
                 FROM alarms al JOIN agents a ON a.agent_id = al.agent_id
                 WHERE al.id = $3 AND {agent}"
            ),
            &[&global, &groups, &alarm_row_id],
        )
        .await?
    else {
        return Ok(Change::NotFound);
    };
    let args: Vec<String> =
        serde_json::from_value(alarm.get::<_, serde_json::Value>(4)).unwrap_or_default();
    let exe: Option<String> = alarm.get(3);
    let (agent_id, exe, hash) = match kind {
        "host" => (Some(alarm.get::<_, String>(2)), None, None),
        "program" => (None, exe, None),
        _ => (None, exe, Some(alarms::args_sha256(&args))),
    };
    let row = tx
        .query_one(
            &format!(
                "INSERT INTO alarm_suppressions AS s (rule_set_id, rule_id, scope, agent_id,
                    exe, args_sha256, note, created_by, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING {COLUMNS}"
            ),
            &[
                &alarm.get::<_, String>(0),
                &alarm.get::<_, String>(1),
                &kind,
                &agent_id,
                &exe,
                &hash,
                &note.trim(),
                &actor,
                &now,
            ],
        )
        .await?;
    let created = suppression(&row);
    audit(&tx, actor, "alarm.suppression.created", &created).await?;
    tx.commit().await?;
    Ok(Change::Done(created))
}

/// Removes suppression `id` if the caller may see it; the row stays.
pub async fn remove(
    client: &mut Client,
    scope: &AgentScope,
    id: i64,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Change, StoreError> {
    let (global, groups) = params(scope);
    let tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt(
            &format!(
                "UPDATE alarm_suppressions s SET removed_at = $4, removed_by = $5
                 WHERE s.id = $3 AND s.removed_at IS NULL AND {}
                 RETURNING {COLUMNS}",
                visible_sql()
            ),
            &[&global, &groups, &id, &now, &actor],
        )
        .await?
    else {
        return Ok(Change::NotFound);
    };
    let removed = suppression(&row);
    audit(&tx, actor, "alarm.suppression.removed", &removed).await?;
    tx.commit().await?;
    Ok(Change::Done(removed))
}
