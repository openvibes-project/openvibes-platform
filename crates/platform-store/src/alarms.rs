//! Threat alarms (protocol P14): what ingest stores from an `AlarmBatch`.
//!
//! An alarm is one row per `(agent, alarm_id)`. A resend raises `count` and
//! `last_seen`, never lowers them, and changes nothing else. Suppressions
//! are applied at insert: a match is stored closed as a false positive, so
//! nothing is lost silently.

use std::collections::BTreeSet;

use chrono::{DateTime, NaiveDate, Utc};
use deadpool_postgres::Client;
use openvibes_core::Alarm;
use sha2::{Digest, Sha256};

use crate::{StoreError, wire};

/// Who ingest writes into triage columns and history.
const INGEST: &str = "ingest";
/// Triage note on test alarms, closed on arrival (`rules::TEST_RULES`).
pub const TEST_NOTE: &str = "Test: closed automatically";

/// One alarm, checked and ready to store.
#[derive(Clone, Debug)]
pub struct StoredAlarm {
    /// Original bounded detection evidence, absent for legacy observations.
    pub detection: Option<serde_json::Value>,
    /// The agent's id, unique per agent.
    pub alarm_id: String,
    /// Rule set that raised it.
    pub rule_set_id: String,
    /// Its version.
    pub rule_set_version: i64,
    /// Rule that raised it.
    pub rule_id: String,
    /// Its version.
    pub rule_version: i64,
    /// Finding severity name.
    pub severity: String,
    /// 0 to 100.
    pub confidence: i16,
    /// The rule's message.
    pub message: String,
    /// First start that matched.
    pub first_seen: DateTime<Utc>,
    /// Latest start that matched.
    pub last_seen: DateTime<Utc>,
    /// How many starts matched.
    pub count: i64,
    /// The process (masked args) as sent.
    pub process: serde_json::Value,
    /// Its ancestors, nearest first, as sent.
    pub ancestors: serde_json::Value,
    /// The process exe, for `program` and `command` suppressions.
    pub exe: String,
    /// [`args_sha256`] of the process args, for `command` suppressions.
    pub args_sha256: String,
}

/// SHA-256 (hex) of the masked args as a JSON array, exactly as sent, so
/// `["a\u{0}b"]` and `["a", "b"]` differ. `truncated` is not part of it.
/// The console derives `command` suppressions with the same function.
#[must_use]
pub fn args_sha256(args: &[String]) -> String {
    let json = serde_json::to_vec(args).unwrap_or_default();
    Sha256::digest(json)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Checks one alarm against what the store can hold: a time Postgres can
/// represent, not beyond the clock-skew allowance (`latest`), not older
/// than retention (`oldest`), and a day with an `alarms` partition. The
/// reason on refusal names the skip counter.
pub fn row(
    alarm: &Alarm,
    oldest: DateTime<Utc>,
    latest: DateTime<Utc>,
    partitions: &BTreeSet<NaiveDate>,
) -> Result<StoredAlarm, &'static str> {
    let first_seen =
        DateTime::from_timestamp_millis(alarm.first_seen_unix_ms).ok_or("out_of_range")?;
    let last_seen =
        DateTime::from_timestamp_millis(alarm.last_seen_unix_ms).ok_or("out_of_range")?;
    if first_seen > latest || last_seen > latest {
        return Err("future_observation");
    }
    if first_seen < oldest {
        return Err("retention_expired");
    }
    if !partitions.contains(&first_seen.date_naive()) {
        return Err("unstorable");
    }
    Ok(StoredAlarm {
        detection: alarm
            .detection
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| "out_of_range")?,
        alarm_id: alarm.alarm_id.as_str().to_owned(),
        rule_set_id: alarm.rule_set_id.as_str().to_owned(),
        rule_set_version: i64::try_from(alarm.rule_set_version).map_err(|_| "out_of_range")?,
        rule_id: alarm.rule_id.as_str().to_owned(),
        rule_version: i64::try_from(alarm.rule_version).map_err(|_| "out_of_range")?,
        severity: wire::severity(alarm.severity).to_owned(),
        confidence: i16::from(alarm.confidence.value()),
        message: alarm.message.clone(),
        first_seen,
        last_seen,
        count: i64::from(alarm.count),
        process: serde_json::to_value(&alarm.process).map_err(|_| "out_of_range")?,
        ancestors: serde_json::to_value(&alarm.ancestors).map_err(|_| "out_of_range")?,
        exe: alarm.process.exe.clone(),
        args_sha256: args_sha256(&alarm.process.args),
    })
}

/// What [`insert_batch`] did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Stored {
    /// New alarms.
    pub stored: u32,
    /// Known alarms whose count or last seen grew.
    pub raised: u32,
    /// New alarms closed by a suppression (also counted in `stored`).
    pub suppressed: u32,
}

struct Suppression {
    id: i64,
    rule_set_id: String,
    rule_id: String,
    scope: String,
    agent_id: Option<String>,
    exe: Option<String>,
    args_sha256: Option<String>,
}

impl Suppression {
    fn matches(&self, agent_id: &str, alarm: &StoredAlarm) -> bool {
        self.rule_set_id == alarm.rule_set_id
            && self.rule_id == alarm.rule_id
            && match self.scope.as_str() {
                "host" => self.agent_id.as_deref() == Some(agent_id),
                "program" => self.exe.as_deref() == Some(alarm.exe.as_str()),
                "command" => {
                    self.exe.as_deref() == Some(alarm.exe.as_str())
                        && self.args_sha256.as_deref() == Some(alarm.args_sha256.as_str())
                }
                _ => false,
            }
    }
}

/// Stores `alarms` for `agent_id` in one transaction and keeps the largest
/// `dropped_total` the agent reported.
pub async fn insert_batch(
    client: &mut Client,
    agent_id: &str,
    dropped_total: u64,
    alarms: &[StoredAlarm],
    now: DateTime<Utc>,
) -> Result<Stored, StoreError> {
    let transaction = client.transaction().await?;
    let dropped = i64::try_from(dropped_total).unwrap_or(i64::MAX);
    transaction
        .execute(
            "UPDATE agents
             SET alarms_dropped_total = GREATEST(COALESCE(alarms_dropped_total, 0), $2)
             WHERE agent_id = $1",
            &[&agent_id, &dropped],
        )
        .await?;
    let rule_sets: Vec<&str> = alarms
        .iter()
        .map(|alarm| alarm.rule_set_id.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let suppressions: Vec<Suppression> = transaction
        .query(
            "SELECT id, rule_set_id, rule_id, scope, agent_id, exe, args_sha256
             FROM alarm_suppressions
             WHERE removed_at IS NULL AND rule_set_id = ANY($1)",
            &[&rule_sets],
        )
        .await?
        .iter()
        .map(|row| Suppression {
            id: row.get(0),
            rule_set_id: row.get(1),
            rule_id: row.get(2),
            scope: row.get(3),
            agent_id: row.get(4),
            exe: row.get(5),
            args_sha256: row.get(6),
        })
        .collect();
    let mut done = Stored::default();
    for alarm in alarms {
        // ponytail: one lookup per alarm (≤100 per batch, indexed); a
        // concurrent batch from the same agent could race it, but an agent
        // delivers its queue serially.
        let known = transaction
            .query_opt(
                "SELECT id, first_seen_day, count, last_seen, state,
                    state = 'accepted_risk' AND accepted_until <= $3, rule_set_id, rule_set_version, rule_id, rule_version FROM alarms
                 WHERE agent_id = $1 AND alarm_id = $2 LIMIT 1",
                &[&agent_id, &alarm.alarm_id, &now],
            )
            .await?;
        if let Some(known) = known {
            let (id, day): (i64, NaiveDate) = (known.get(0), known.get(1));
            let (count, last_seen, state): (i64, DateTime<Utc>, String) =
                (known.get(2), known.get(3), known.get(4));
            let risk_expired: bool = known.get(5);
            if known.get::<_, String>(6) != alarm.rule_set_id
                || known.get::<_, i64>(7) != alarm.rule_set_version
                || known.get::<_, String>(8) != alarm.rule_id
                || known.get::<_, i64>(9) != alarm.rule_version
            {
                continue;
            }
            if alarm.count <= count && alarm.last_seen <= last_seen {
                continue;
            }
            transaction
                .execute(
                    "UPDATE alarms SET count = GREATEST(count, $3),
                        process = CASE WHEN $4 > last_seen THEN $5 ELSE process END,
                        ancestors = CASE WHEN $4 > last_seen THEN $6 ELSE ancestors END,
                        detection = CASE WHEN $4 > last_seen THEN $7 ELSE detection END,
                        last_seen = GREATEST(last_seen, $4)
                     WHERE id = $1 AND first_seen_day = $2",
                    &[
                        &id,
                        &day,
                        &alarm.count,
                        &alarm.last_seen,
                        &alarm.process,
                        &alarm.ancestors,
                        &alarm.detection,
                    ],
                )
                .await?;
            // Recurrence reopens a mitigated alarm, or one whose accepted
            // risk has expired, as findings do; a false positive or an
            // unexpired accepted risk stays closed.
            let test = crate::rules::is_test_rule(&alarm.rule_set_id, &alarm.rule_id);
            if !test && alarm.count > count && (state == "mitigated" || risk_expired) {
                transaction
                    .execute(
                        "UPDATE alarms SET state = 'open', accepted_until = NULL,
                            triage_version = triage_version + 1,
                            triage_updated_at = $3, triage_updated_by = $4
                         WHERE id = $1 AND first_seen_day = $2",
                        &[&id, &day, &now, &INGEST],
                    )
                    .await?;
                history(
                    &transaction,
                    id,
                    day,
                    Some(state.as_str()),
                    "open",
                    "recurred",
                    now,
                )
                .await?;
            }
            done.raised += 1;
            continue;
        }
        let suppression = suppressions
            .iter()
            .find(|suppression| suppression.matches(agent_id, alarm));
        // A test alarm (openvibes-test) is closed on arrival: it proves the
        // pipeline works and never needs triage. A recurrence keeps it closed.
        let test = crate::rules::is_test_rule(&alarm.rule_set_id, &alarm.rule_id);
        let (state, note) = match suppression {
            Some(suppression) => (
                "false_positive",
                Some(format!("suppressed by #{}", suppression.id)),
            ),
            None if test => ("mitigated", Some(TEST_NOTE.to_owned())),
            None => ("open", None),
        };
        let closed = suppression.is_some() || test;
        let triage_at = closed.then_some(now);
        let triage_by = closed.then_some(INGEST);
        let id: i64 = transaction
            .query_one(
                "INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id,
                    rule_set_version, rule_id, rule_version, severity, confidence, message,
                    first_seen, last_seen, count, process, ancestors, received_at,
                    suppressed_by, state, note, triage_updated_at, triage_updated_by, detection)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                    $15, $16, $17, $18, $19, $20, $21, $22)
                 RETURNING id",
                &[
                    &alarm.first_seen.date_naive(),
                    &agent_id,
                    &alarm.alarm_id,
                    &alarm.rule_set_id,
                    &alarm.rule_set_version,
                    &alarm.rule_id,
                    &alarm.rule_version,
                    &alarm.severity,
                    &alarm.confidence,
                    &alarm.message,
                    &alarm.first_seen,
                    &alarm.last_seen,
                    &alarm.count,
                    &alarm.process,
                    &alarm.ancestors,
                    &now,
                    &suppression.map(|suppression| suppression.id),
                    &state,
                    &note,
                    &triage_at,
                    &triage_by,
                    &alarm.detection,
                ],
            )
            .await?
            .get(0);
        done.stored += 1;
        if let Some(note) = &note {
            let day = alarm.first_seen.date_naive();
            history(&transaction, id, day, None, state, note, now).await?;
            if suppression.is_some() {
                done.suppressed += 1;
            }
        }
    }
    transaction.commit().await?;
    Ok(done)
}

async fn history(
    transaction: &deadpool_postgres::Transaction<'_>,
    alarm_row_id: i64,
    day: NaiveDate,
    from: Option<&str>,
    to: &str,
    note: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO alarm_triage_history (first_seen_day, alarm_row_id, from_state,
                to_state, note, changed_at, changed_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[&day, &alarm_row_id, &from, &to, &note, &now, &INGEST],
        )
        .await?;
    Ok(())
}
