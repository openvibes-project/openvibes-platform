//! Alarms from network devices (spec 2026-10-10-network-device-alarms §3–4),
//! stored by `openvibes-netlog`. Same rules as agent alarms: a resend
//! raises `count` and `last_seen`, a recurrence reopens a mitigated alarm or
//! an expired accepted risk, and a suppression closes a new alarm as a
//! false positive with one history row.

use chrono::{DateTime, NaiveDate, Utc};
use deadpool_postgres::Client;

use crate::{StoreError, alarms::history};

/// The rule set every UniFi alarm carries.
pub const RULE_SET: &str = "device-unifi";
/// Who netlog writes into triage columns and history.
pub const NETLOG: &str = "netlog";

/// One collapsed device alarm, validated by netlog.
#[derive(Clone, Debug, PartialEq)]
pub struct DeviceAlarm {
    /// The device that sent it.
    pub device_id: i64,
    /// Netlog's id, unique per device.
    pub alarm_id: String,
    /// `ips.<signature_id>`.
    pub rule_id: String,
    /// Finding severity name.
    pub severity: String,
    /// 0 to 100.
    pub confidence: i16,
    /// `<signature>: <msg>`.
    pub message: String,
    /// First event (receive time).
    pub first_seen: DateTime<Utc>,
    /// Latest event (receive time).
    pub last_seen: DateTime<Utc>,
    /// Total events collapsed into it so far.
    pub count: i64,
    /// The validated network fields.
    pub network: serde_json::Value,
}

/// What one batch did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceStored {
    /// New alarms.
    pub stored: u32,
    /// Known alarms whose count or last seen grew.
    pub raised: u32,
    /// New alarms closed by a suppression (also in `stored`).
    pub suppressed: u32,
    /// Skipped: no `alarms` partition for its first day.
    pub unstorable: u32,
}

/// Stores `alarms` in one transaction.
pub async fn insert_batch(
    client: &mut Client,
    alarms: &[DeviceAlarm],
    now: DateTime<Utc>,
) -> Result<DeviceStored, StoreError> {
    let partitions = crate::partition_days_of(client, "alarms").await?;
    let tx = client.transaction().await?;
    let suppressions: Vec<(i64, String, Option<i64>)> = tx
        .query(
            "SELECT id, rule_id, device_id FROM alarm_suppressions
             WHERE removed_at IS NULL AND rule_set_id = $1 AND scope IN ('device', 'signature')
             ORDER BY id",
            &[&RULE_SET],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    let mut done = DeviceStored::default();
    for alarm in alarms {
        let day = alarm.first_seen.date_naive();
        if !partitions.contains(&day) {
            done.unstorable += 1;
            continue;
        }
        let known = tx
            .query_opt(
                "SELECT id, first_seen_day, count, last_seen, state,
                    state = 'accepted_risk' AND accepted_until <= $3
                 FROM alarms WHERE device_id = $1 AND alarm_id = $2 LIMIT 1",
                &[&alarm.device_id, &alarm.alarm_id, &now],
            )
            .await?;
        if let Some(known) = known {
            let (id, day, count, last_seen, state, expired): (
                i64,
                NaiveDate,
                i64,
                DateTime<Utc>,
                String,
                bool,
            ) = (
                known.get(0),
                known.get(1),
                known.get(2),
                known.get(3),
                known.get(4),
                known.get(5),
            );
            if alarm.count <= count && alarm.last_seen <= last_seen {
                continue;
            }
            tx.execute(
                "UPDATE alarms SET count = GREATEST(count, $3), last_seen = GREATEST(last_seen, $4),
                    network = CASE WHEN $4 > last_seen THEN $5 ELSE network END
                 WHERE id = $1 AND first_seen_day = $2",
                &[&id, &day, &alarm.count, &alarm.last_seen, &alarm.network],
            )
            .await?;
            if alarm.count > count && (state == "mitigated" || expired) {
                tx.execute(
                    "UPDATE alarms SET state = 'open', accepted_until = NULL,
                        triage_version = triage_version + 1,
                        triage_updated_at = $3, triage_updated_by = $4
                     WHERE id = $1 AND first_seen_day = $2",
                    &[&id, &day, &now, &NETLOG],
                )
                .await?;
                history(
                    &tx,
                    id,
                    day,
                    Some(state.as_str()),
                    "open",
                    "recurred",
                    now,
                    NETLOG,
                )
                .await?;
            }
            done.raised += 1;
            continue;
        }
        let suppression = suppressions
            .iter()
            .find(|(_, rule, device)| {
                *rule == alarm.rule_id && device.is_none_or(|d| d == alarm.device_id)
            })
            .map(|(id, ..)| *id);
        let (state, note) = match suppression {
            Some(id) => ("false_positive", Some(format!("suppressed by #{id}"))),
            None => ("open", None),
        };
        let triage_at = suppression.map(|_| now);
        let triage_by = suppression.map(|_| NETLOG);
        let id: i64 = tx
            .query_one(
                "INSERT INTO alarms (first_seen_day, source, device_id, alarm_id, rule_set_id,
                    rule_set_version, rule_id, rule_version, severity, confidence, message,
                    first_seen, last_seen, count, network, received_at, suppressed_by, state,
                    note, triage_updated_at, triage_updated_by)
                 VALUES ($1, 'device', $2, $3, $4, 0, $5, 0, $6, $7, $8, $9, $10, $11, $12,
                    $13, $14, $15, $16, $17, $18)
                 RETURNING id",
                &[
                    &day,
                    &alarm.device_id,
                    &alarm.alarm_id,
                    &RULE_SET,
                    &alarm.rule_id,
                    &alarm.severity,
                    &alarm.confidence,
                    &alarm.message,
                    &alarm.first_seen,
                    &alarm.last_seen,
                    &alarm.count,
                    &alarm.network,
                    &now,
                    &suppression,
                    &state,
                    &note,
                    &triage_at,
                    &triage_by,
                ],
            )
            .await?
            .get(0);
        done.stored += 1;
        if let Some(note) = &note {
            history(&tx, id, day, None, state, note, now, NETLOG).await?;
            done.suppressed += 1;
        }
    }
    tx.commit().await?;
    Ok(done)
}
