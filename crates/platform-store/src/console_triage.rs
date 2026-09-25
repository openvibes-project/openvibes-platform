//! Versioned human workflow state for the current observation of one finding.

use chrono::{DateTime, Utc};
use tokio_postgres::Transaction;

use crate::{Client, StoreError};

/// Safe current triage view joined with the latest detector version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriageRecord {
    /// Workflow state (`open`, `investigating`, or a completed state).
    pub state: String,
    /// Detector rule version the workflow row is based on.
    pub rule_version: i64,
    /// Assigned active analyst UUID.
    pub assigned_to_id: Option<String>,
    /// Assigned analyst username.
    pub assigned_to_username: Option<String>,
    /// Bounded operator note.
    pub note: Option<String>,
    /// Required expiry for accepted risk.
    pub accepted_until: Option<DateTime<Utc>>,
    /// Monotonic write version (zero means default Open with no saved row).
    pub version: i64,
    /// Last update time, absent for default Open.
    pub updated_at: Option<DateTime<Utc>>,
    /// Human actor for the last change, or `system` for automatic reopening.
    pub updated_by: Option<String>,
}

/// Outcome of a version-checked triage write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TriageUpdate {
    /// The transaction saved the requested state.
    Updated(TriageRecord),
    /// The observation no longer exists.
    NotFound,
    /// The caller supplied an out-of-date version.
    Stale(TriageRecord),
    /// The requested transition is not allowed.
    InvalidTransition(TriageRecord),
    /// The requested assignee is not an enabled Analyst or Admin.
    AssigneeUnavailable,
    /// The note or risk expiry violates the state contract.
    InvalidFields,
}

/// Reads current triage for a live latest finding; absent triage is default Open.
pub async fn get(
    client: &Client,
    agent_id: &str,
    rule_set_id: &str,
    rule_id: &str,
) -> Result<Option<TriageRecord>, StoreError> {
    let row = client.query_opt(
        "SELECT COALESCE(t.state,'open'),COALESCE(t.rule_version,c.rule_version),t.assigned_to::text,u.username,t.note,t.accepted_until,COALESCE(t.version,0),t.updated_at,t.updated_by
         FROM current_findings c LEFT JOIN console_finding_triage t USING(agent_id,rule_set_id,rule_id)
         LEFT JOIN console_users u ON u.user_id=t.assigned_to
         WHERE c.agent_id=$1 AND c.rule_set_id=$2 AND c.rule_id=$3",
        &[&agent_id,&rule_set_id,&rule_id],
    ).await?;
    Ok(row.map(record_from_row))
}

/// Updates triage with an ETag version check and atomic history/audit writes.
#[allow(clippy::too_many_arguments)]
pub async fn update(
    client: &mut Client,
    agent_id: &str,
    rule_set_id: &str,
    rule_id: &str,
    expected_version: i64,
    state: &str,
    assigned_to_username: Option<&str>,
    note: Option<&str>,
    accepted_until: Option<DateTime<Utc>>,
    actor_id: &str,
    now: DateTime<Utc>,
) -> Result<TriageUpdate, StoreError> {
    if !matches!(
        state,
        "open" | "investigating" | "mitigated" | "accepted_risk" | "false_positive"
    ) || note.is_some_and(|value| value.trim().is_empty() || value.chars().count() > 4000)
        || ((state == "accepted_risk") != accepted_until.is_some())
        || accepted_until.is_some_and(|value| value <= now)
    {
        return Ok(TriageUpdate::InvalidFields);
    }

    let tx = client.transaction().await?;
    let Some(current)=tx.query_opt("SELECT rule_version FROM current_findings WHERE agent_id=$1 AND rule_set_id=$2 AND rule_id=$3 FOR UPDATE",&[&agent_id,&rule_set_id,&rule_id]).await? else { tx.rollback().await?;return Ok(TriageUpdate::NotFound); };
    let rule_version: i64 = current.get(0);
    let old=tx.query_opt("SELECT t.state,t.assigned_to::text,u.username,t.note,t.accepted_until,t.version,t.updated_at,t.updated_by,t.rule_version
        FROM console_finding_triage t LEFT JOIN console_users u ON u.user_id=t.assigned_to
        WHERE t.agent_id=$1 AND t.rule_set_id=$2 AND t.rule_id=$3 FOR UPDATE OF t",&[&agent_id,&rule_set_id,&rule_id]).await?;
    let previous = old
        .as_ref()
        .map(record_from_triage_row)
        .unwrap_or(TriageRecord {
            state: "open".into(),
            rule_version,
            assigned_to_id: None,
            assigned_to_username: None,
            note: None,
            accepted_until: None,
            version: 0,
            updated_at: None,
            updated_by: None,
        });
    if previous.version != expected_version {
        tx.rollback().await?;
        return Ok(TriageUpdate::Stale(previous));
    }
    if !transition_allowed(&previous.state, state) {
        tx.rollback().await?;
        return Ok(TriageUpdate::InvalidTransition(previous));
    }
    if matches!(state, "mitigated" | "accepted_risk" | "false_positive") && note.is_none() {
        tx.rollback().await?;
        return Ok(TriageUpdate::InvalidFields);
    }
    let assignee = if let Some(username) = assigned_to_username {
        tx.query_opt("SELECT u.user_id::text,u.username FROM console_users u WHERE u.username=$1 AND u.enabled AND EXISTS(SELECT 1 FROM console_role_bindings b WHERE b.user_id=u.user_id AND b.role_id IN ('analyst','admin') AND b.revoked_at IS NULL)",&[&username]).await?
            .map(|row|(row.get::<_,String>(0),row.get::<_,String>(1)))
    } else {
        None
    };
    if assigned_to_username.is_some() && assignee.is_none() {
        tx.rollback().await?;
        return Ok(TriageUpdate::AssigneeUnavailable);
    }
    let assigned_to_id = assignee.as_ref().map(|value| value.0.clone());
    let assigned_name = assignee.as_ref().map(|value| value.1.clone());
    let changed = previous.state != state
        || previous.assigned_to_id != assigned_to_id
        || previous.note.as_deref() != note
        || previous.accepted_until != accepted_until;
    if !changed {
        tx.rollback().await?;
        return Ok(TriageUpdate::Updated(previous));
    }
    let version = expected_version + 1;
    tx.execute("INSERT INTO console_finding_triage(agent_id,rule_set_id,rule_id,state,rule_version,assigned_to,note,accepted_until,version,updated_at,updated_by)
        VALUES($1,$2,$3,$4,$5,$6::text::uuid,$7,$8,$9,$10,$11)
        ON CONFLICT(agent_id,rule_set_id,rule_id) DO UPDATE SET state=EXCLUDED.state,rule_version=EXCLUDED.rule_version,assigned_to=EXCLUDED.assigned_to,note=EXCLUDED.note,accepted_until=EXCLUDED.accepted_until,version=EXCLUDED.version,updated_at=EXCLUDED.updated_at,updated_by=EXCLUDED.updated_by",
        &[&agent_id,&rule_set_id,&rule_id,&state,&rule_version,&assigned_to_id,&note,&accepted_until,&version,&now,&actor_id]).await?;
    let target = format!("{agent_id}:{rule_set_id}:{rule_id}");
    tx.execute("INSERT INTO console_finding_triage_history(agent_id,rule_set_id,rule_id,from_state,to_state,note,changed_at,changed_by,assigned_to,accepted_until,rule_version)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::text::uuid,$10,$11)",&[&agent_id,&rule_set_id,&rule_id,&Some(previous.state.as_str()),&state,&note,&now,&actor_id,&assigned_to_id,&accepted_until,&rule_version]).await?;
    tx.execute("INSERT INTO audit_log(actor,action,target,result,detail,actor_kind,actor_id,actor_display,target_kind,target_id)
        VALUES($1,'finding.triage.changed','finding_triage','success',jsonb_build_object('from_state',$2::text,'to_state',$3::text,'assigned_to',$4::text,'accepted_until',$5::text,'version',$6::bigint),'user',$1,$1,'finding_triage',$7)",&[&actor_id,&previous.state,&state,&assigned_name,&accepted_until.map(|value|value.to_rfc3339()),&version,&target]).await?;
    tx.commit().await?;
    Ok(TriageUpdate::Updated(TriageRecord {
        state: state.to_owned(),
        rule_version,
        assigned_to_id,
        assigned_to_username: assigned_name,
        note: note.map(str::to_owned),
        accepted_until,
        version,
        updated_at: Some(now),
        updated_by: Some(actor_id.to_owned()),
    }))
}

fn transition_allowed(from: &str, to: &str) -> bool {
    from == to
        || matches!(
            (from, to),
            ("open", "investigating")
                | ("investigating", "mitigated")
                | ("investigating", "accepted_risk")
                | ("investigating", "false_positive")
        )
}

fn record_from_row(row: tokio_postgres::Row) -> TriageRecord {
    TriageRecord {
        state: row.get(0),
        rule_version: row.get(1),
        assigned_to_id: row.get(2),
        assigned_to_username: row.get(3),
        note: row.get(4),
        accepted_until: row.get(5),
        version: row.get(6),
        updated_at: row.get(7),
        updated_by: row.get(8),
    }
}

fn record_from_triage_row(row: &tokio_postgres::Row) -> TriageRecord {
    TriageRecord {
        state: row.get(0),
        assigned_to_id: row.get(1),
        assigned_to_username: row.get(2),
        note: row.get(3),
        accepted_until: row.get(4),
        version: row.get(5),
        updated_at: row.get(6),
        updated_by: row.get(7),
        rule_version: row.get(8),
    }
}

/// Reopens completed states when a genuinely new latest observation advances.
pub(crate) async fn reopen_on_observation(
    transaction: &Transaction<'_>,
    agent_id: &str,
    rule_set_id: &str,
    rule_id: &str,
    finding_id: &str,
    observed_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let latest=transaction.query_opt("SELECT last_finding_id,rule_version FROM current_findings WHERE agent_id=$1 AND rule_set_id=$2 AND rule_id=$3 FOR UPDATE",&[&agent_id,&rule_set_id,&rule_id]).await?;
    let Some(latest) = latest else {
        return Ok(());
    };
    if latest.get::<_, String>(0) != finding_id {
        return Ok(());
    }
    let current_rule_version: i64 = latest.get(1);
    let row=transaction.query_opt("SELECT state,rule_version,accepted_until,version FROM console_finding_triage WHERE agent_id=$1 AND rule_set_id=$2 AND rule_id=$3 FOR UPDATE",&[&agent_id,&rule_set_id,&rule_id]).await?;
    let Some(row) = row else {
        return Ok(());
    };
    let state: String = row.get(0);
    let old_rule_version: i64 = row.get(1);
    let accepted_until: Option<DateTime<Utc>> = row.get(2);
    let version: i64 = row.get(3);
    let reason = match state.as_str() {
        "mitigated" => Some("new_observation"),
        "accepted_risk" if accepted_until.is_some_and(|expiry| observed_at > expiry) => {
            Some("accepted_risk_expired")
        }
        "false_positive" if current_rule_version > old_rule_version => Some("rule_version_changed"),
        _ => None,
    };
    let Some(reason) = reason else {
        return Ok(());
    };
    transaction.execute("UPDATE console_finding_triage SET state='open',rule_version=$4,assigned_to=NULL,note=NULL,accepted_until=NULL,version=$5,updated_at=$6,updated_by='system' WHERE agent_id=$1 AND rule_set_id=$2 AND rule_id=$3",&[&agent_id,&rule_set_id,&rule_id,&current_rule_version,&(version+1),&now]).await?;
    transaction.execute("INSERT INTO console_finding_triage_history(agent_id,rule_set_id,rule_id,from_state,to_state,note,changed_at,changed_by,assigned_to,accepted_until,rule_version) VALUES($1,$2,$3,$4,'open',NULL,$5,'system',NULL,NULL,$6)",&[&agent_id,&rule_set_id,&rule_id,&state,&now,&current_rule_version]).await?;
    let target = format!("{agent_id}:{rule_set_id}:{rule_id}");
    transaction.execute("INSERT INTO audit_log(actor,action,target,result,detail,actor_kind,actor_id,actor_display,target_kind,target_id) VALUES('system','finding.triage.reopened','finding_triage','success',jsonb_build_object('reason',$1::text,'from_state',$2::text,'rule_version',$3::bigint),'system',NULL,'system','finding_triage',$4)",&[&reason,&state,&current_rule_version,&target]).await?;
    Ok(())
}
