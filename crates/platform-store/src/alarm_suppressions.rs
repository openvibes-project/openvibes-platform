//! Alarm suppressions (P14) as the console manages them (roles spec §8).
//! A suppression is always derived from an alarm the caller can see, never
//! typed in: `program` or `command` from that alarm, on its host, a group
//! or all hosts, for 7 days, 30 days or until removed. With approval on it
//! waits for someone else to approve it. Old `host` rows stay valid, and
//! `device`/`signature` rows (made by `openvibes-admin`) are always active.
//! Nothing is deleted: removed, withdrawn and rejected rows stay as history.
//! The writes live in `alarm_suppression_writes.rs`.

use chrono::{DateTime, Utc};
use deadpool_postgres::GenericClient;

pub use crate::alarm_suppression_writes::{decide, remove, request, withdraw};
use crate::{
    Client, StoreError,
    console_read::{AgentScope, agent_visibility},
};

/// What a suppression quiets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum What {
    /// The alarm's program, with any arguments.
    Program,
    /// The alarm's exact command line.
    Command,
}

/// Where a suppression applies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Where {
    /// The source alarm's host.
    Host,
    /// A host group (its uuid as text).
    Group(String),
    /// Every host.
    All,
}

/// A suppression's state; expired is derived from `expires_at`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    /// Waiting for approval.
    Waiting,
    /// Applied to new alarms (until it expires).
    Active,
    /// Refused by an approver.
    Rejected,
    /// Taken back by its requester while waiting.
    Withdrawn,
    /// Removed after being active.
    Removed,
}

impl State {
    /// The stored name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Active => "active",
            Self::Rejected => "rejected",
            Self::Withdrawn => "withdrawn",
            Self::Removed => "removed",
        }
    }

    fn parse(state: &str) -> Self {
        match state {
            "waiting" => Self::Waiting,
            "active" => Self::Active,
            "rejected" => Self::Rejected,
            "withdrawn" => Self::Withdrawn,
            _ => Self::Removed,
        }
    }
}

/// A request to suppress, derived from one alarm.
#[derive(Clone, Debug)]
pub struct Request<'a> {
    /// The platform's id of the source alarm.
    pub alarm_row_id: i64,
    /// Program or command.
    pub what: What,
    /// Its host, a group or all hosts.
    pub place: Where,
    /// 7, 30 or `None` (until removed), counted from activation.
    pub for_days: Option<i32>,
    /// Why, 1 to 4,000 characters.
    pub reason: &'a str,
}

/// One suppression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Suppression {
    /// Its id (alarms name it in "suppressed by #id").
    pub id: i64,
    /// Rule set of the rule.
    pub rule_set_id: String,
    /// Rule it quiets.
    pub rule_id: String,
    /// `program` or `command`; `host` for rows made before schema 55;
    /// `device` or `signature` for network device alarms.
    pub scope: String,
    /// The host, for `host` and for a program/command on one host.
    pub agent_id: Option<String>,
    /// The program, for `program` and `command`.
    pub exe: Option<String>,
    /// SHA-256 of the masked args' JSON array, for `command`.
    pub args_sha256: Option<String>,
    /// The network device, for `device`.
    pub device_id: Option<i64>,
    /// Why (the requester's reason).
    pub note: String,
    /// Who asked for it.
    pub created_by: String,
    /// When.
    pub created_at: DateTime<Utc>,
    /// Its state.
    pub state: State,
    /// Active, but past `expires_at`: it closes nothing any more.
    pub expired: bool,
    /// The group, for a program/command on one group.
    pub host_group_id: Option<String>,
    /// That group's name, while the group exists.
    pub host_group_name: Option<String>,
    /// 7, 30 or `None` (until removed).
    pub for_days: Option<i32>,
    /// When it became active.
    pub activated_at: Option<DateTime<Utc>>,
    /// When it stops applying (activation plus `for_days`).
    pub expires_at: Option<DateTime<Utc>>,
    /// Who approved, rejected or withdrew it.
    pub decided_by: Option<String>,
    /// When.
    pub decided_at: Option<DateTime<Utc>>,
    /// The approver's reason (required to reject).
    pub decision_reason: Option<String>,
    /// The source alarm's platform id; `None` for rows made before schema 55.
    pub alarm_id: Option<i64>,
}

/// Outcome of a write.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // one per request; boxing buys nothing
pub enum Change {
    /// Done; the suppression as it now is.
    Done(Suppression),
    /// The alarm or suppression is absent or outside the caller's reach.
    NotFound,
    /// All hosts needs a caller reaching all hosts.
    NeedsGlobalScope,
    /// The group is not in the caller's reach.
    NotInReach,
    /// The named field (`reason`, `for`, `group`, `command`) is invalid.
    Invalid(String),
    /// Not in a state that allows this (only waiting can be decided or
    /// withdrawn).
    WrongState,
    /// The requester may not decide their own request.
    OwnRequest,
}

/// Which suppressions [`list`] returns.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ListFilter {
    /// One state (`Active` includes expired); `None` for waiting, active
    /// and rejected.
    pub state: Option<State>,
    /// Only those made from this alarm.
    pub alarm_id: Option<i64>,
}

/// Rows per state [`list`] returns at most.
const LIST_LIMIT: i64 = 500;

/// The columns [`suppression`] reads, `now` being the placeholder of the
/// time `expired` is judged at.
fn select(now: &str) -> String {
    format!(
        "SELECT s.id, s.rule_set_id, s.rule_id, s.scope, s.agent_id, s.exe, s.args_sha256,
            s.note, s.created_by, s.created_at, s.device_id, s.state,
            s.state = 'active' AND s.expires_at IS NOT NULL AND s.expires_at <= {now},
            s.host_group_id::text, g.name, s.for_days, s.activated_at, s.expires_at,
            s.decided_by, s.decided_at, s.decision_reason, s.alarm_id
         FROM alarm_suppressions s
         LEFT JOIN console_asset_groups g ON g.asset_group_id = s.host_group_id"
    )
}

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
        device_id: row.get(10),
        state: State::parse(row.get(11)),
        expired: row.get(12),
        host_group_id: row.get(13),
        host_group_name: row.get(14),
        for_days: row.get(15),
        activated_at: row.get(16),
        expires_at: row.get(17),
        decided_by: row.get(18),
        decided_at: row.get(19),
        decision_reason: row.get(20),
        alarm_id: row.get(21),
    }
}

/// Suppression `id` as it now is.
pub(crate) async fn fetch(
    client: &impl GenericClient,
    id: i64,
    now: DateTime<Utc>,
) -> Result<Suppression, StoreError> {
    let query = format!("{} WHERE s.id = $1", select("$2"));
    Ok(suppression(&client.query_one(&query, &[&id, &now]).await?))
}

/// `$1` (global) and `$2` (group ids) for [`in_reach`] and
/// [`agent_visibility`].
pub(crate) fn params(scope: &AgentScope) -> (bool, Vec<String>) {
    (scope.is_global(), scope.group_ids())
}

/// SQL: suppression `s` is within the reach of `$1`/`$2`. A host row if
/// the host is in reach; a group row if the group is in the scope; an
/// all-hosts row for every reader (`all_rows`, ruling 5) but only a
/// global caller otherwise; a device row only for a global caller.
pub(crate) fn in_reach(all_rows: bool) -> String {
    let agent = agent_visibility("a.agent_id", "$1", "$2");
    let all_rows = if all_rows { "true" } else { "$1::boolean" };
    format!(
        "($1::boolean
          OR (s.agent_id IS NOT NULL AND EXISTS (
                SELECT 1 FROM agents a WHERE a.agent_id = s.agent_id AND {agent}))
          OR (s.host_group_id IS NOT NULL AND s.host_group_id::text = ANY($2::text[]))
          OR (s.agent_id IS NULL AND s.host_group_id IS NULL AND s.device_id IS NULL
              AND {all_rows}))"
    )
}

/// Waiting (oldest first), active including expired (newest first) and
/// rejected (newest first) suppressions the caller may read, at most 500
/// of each. Withdrawn and removed ones live in the audit log.
pub async fn list(
    client: &Client,
    read: &AgentScope,
    filter: &ListFilter,
    now: DateTime<Utc>,
) -> Result<Vec<Suppression>, StoreError> {
    let (global, groups) = params(read);
    let state = filter.state.map(State::as_str);
    let order = "CASE WHEN state = 'waiting' THEN created_at END, created_at DESC, id DESC";
    let query = format!(
        "SELECT * FROM (
            SELECT *, row_number() OVER (PARTITION BY state ORDER BY {order}) AS n
            FROM ({} WHERE s.state IN ('waiting', 'active', 'rejected')
                AND ($4::text IS NULL OR s.state = $4) AND ($5::bigint IS NULL OR s.alarm_id = $5)
                AND {}) x) y
         WHERE n <= $6
         ORDER BY array_position(ARRAY['waiting', 'active', 'rejected'], state), {order}",
        select("$3"),
        in_reach(true)
    );
    let rows = client
        .query(
            &query,
            &[
                &global,
                &groups,
                &now,
                &state,
                &filter.alarm_id,
                &LIST_LIMIT,
            ],
        )
        .await?;
    Ok(rows.iter().map(suppression).collect())
}

/// `host`, `group`, `all` or `device`.
fn place(suppression: &Suppression) -> &'static str {
    if suppression.device_id.is_some() {
        "device"
    } else if suppression.agent_id.is_some() {
        "host"
    } else if suppression.host_group_id.is_some() {
        "group"
    } else {
        "all"
    }
}

pub(crate) async fn audit(
    tx: &deadpool_postgres::Transaction<'_>,
    actor: &str,
    action: &str,
    suppression: &Suppression,
) -> Result<(), StoreError> {
    let detail = serde_json::json!({
        "rule_set_id": suppression.rule_set_id,
        "rule_id": suppression.rule_id,
        "what": suppression.scope,
        "where": place(suppression),
        "host_group_id": suppression.host_group_id,
        "agent_id": suppression.agent_id,
        "exe": suppression.exe,
        "device_id": suppression.device_id,
        "for_days": suppression.for_days,
        "reason": suppression.note,
        "decision_reason": suppression.decision_reason,
        "state": suppression.state.as_str(),
    });
    tx.execute(
        "INSERT INTO audit_log (actor, action, target, result, detail, actor_kind, actor_id,
            actor_display, target_kind, target_id)
         VALUES ($1, $2, 'alarm_suppression', 'success', $3, 'user', $1, $1,
            'alarm_suppression', $4)",
        &[&actor, &action, &detail, &suppression.id.to_string()],
    )
    .await?;
    Ok(())
}

/// A reason after trimming: 1 to 4,000 characters.
pub(crate) fn valid_reason(reason: &str) -> bool {
    !reason.is_empty() && reason.chars().count() <= 4000
}

/// Creates a suppression from network device alarm `alarm_row_id`:
/// `device` quiets its rule on that device, `signature` on every device
/// (spec 2026-10-10 §4). Global callers only (no asset group holds a
/// device yet). Always active at once (ruling 9); it applies to alarms
/// stored from now on.
pub async fn create_for_device(
    client: &mut Client,
    alarm_row_id: i64,
    kind: &str,
    note: &str,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Change, StoreError> {
    if !matches!(kind, "device" | "signature") {
        return Ok(Change::Invalid("scope".into()));
    }
    if !valid_reason(note.trim()) {
        return Ok(Change::Invalid("reason".into()));
    }
    let tx = client.transaction().await?;
    let Some(alarm) = tx
        .query_opt(
            "SELECT rule_set_id, rule_id, device_id FROM alarms
             WHERE id = $1 AND source = 'device'",
            &[&alarm_row_id],
        )
        .await?
    else {
        return Ok(Change::NotFound);
    };
    let device: Option<i64> = (kind == "device").then(|| alarm.get(2));
    let id: i64 = tx
        .query_one(
            "INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, device_id, note,
                created_by, created_at, state, activated_at, alarm_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $7, $8) RETURNING id",
            &[
                &alarm.get::<_, String>(0),
                &alarm.get::<_, String>(1),
                &kind,
                &device,
                &note.trim(),
                &actor,
                &now,
                &alarm_row_id,
            ],
        )
        .await?
        .get(0);
    let created = fetch(&tx, id, now).await?;
    audit(&tx, actor, "alarm.suppression.created", &created).await?;
    tx.commit().await?;
    Ok(Change::Done(created))
}
