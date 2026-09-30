use std::collections::BTreeSet;

use chrono::{Duration, NaiveDate};
use deadpool_postgres::Client;

use crate::StoreError;

/// The tables partitioned by day, kept with the same retention.
const PARTITIONED: [&str; 3] = ["findings", "alarms", "alarm_triage_history"];

/// Partition names are built only from constants and dates, never from input.
fn partition_name(table: &str, day: NaiveDate) -> String {
    format!("{table}_{}", day.format("%Y%m%d"))
}

/// The days that have a `findings` partition.
pub async fn partition_days(client: &Client) -> Result<BTreeSet<NaiveDate>, StoreError> {
    partition_days_of(client, "findings").await
}

/// The days that have a partition of `table`, one of `findings`, `alarms` or `alarm_triage_history`.
pub async fn partition_days_of(
    client: &Client,
    table: &str,
) -> Result<BTreeSet<NaiveDate>, StoreError> {
    let rows = client
        .query(
            "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
             WHERE i.inhparent = $1::text::regclass",
            &[&table],
        )
        .await?;
    let prefix = format!("{table}_");
    Ok(rows
        .iter()
        .filter_map(|row| {
            let name: String = row.get(0);
            NaiveDate::parse_from_str(name.strip_prefix(&prefix)?, "%Y%m%d").ok()
        })
        .collect())
}

/// Creates daily partitions of every day-partitioned table (findings, alarms,
/// alarm triage history) for `today` and
/// the `days_ahead` days after it that do not exist yet; returns how many
/// were created.
pub async fn ensure_partitions(
    client: &Client,
    today: NaiveDate,
    days_ahead: u32,
) -> Result<u32, StoreError> {
    locked(client, create_partitions(client, today, days_ahead)).await
}

/// Advisory lock key for partition maintenance ("ovpa").
const PARTITION_LOCK: i64 = 0x6f76_7061;

/// Runs `work` holding the partition lock, so concurrent maintenance runs
/// wait instead of racing on the same partitions. The session lock is
/// released on every path, errors included, so a pooled connection never
/// keeps it.
async fn locked<T>(
    client: &Client,
    work: impl std::future::Future<Output = Result<T, StoreError>>,
) -> Result<T, StoreError> {
    client
        .execute("SELECT pg_advisory_lock($1)", &[&PARTITION_LOCK])
        .await?;
    let result = work.await;
    let unlocked = client
        .execute("SELECT pg_advisory_unlock($1)", &[&PARTITION_LOCK])
        .await;
    let value = result?;
    unlocked?;
    Ok(value)
}

async fn create_partitions(
    client: &Client,
    today: NaiveDate,
    days_ahead: u32,
) -> Result<u32, StoreError> {
    let mut created = 0;
    for table in PARTITIONED {
        let existing = partition_days_of(client, table).await?;
        for offset in 0..=i64::from(days_ahead) {
            let day = today + Duration::days(offset);
            if existing.contains(&day) {
                continue;
            }
            let next = day + Duration::days(1);
            client
                .batch_execute(&format!(
                    "CREATE TABLE IF NOT EXISTS {} PARTITION OF {table}
                     FOR VALUES FROM ('{}') TO ('{}')",
                    partition_name(table, day),
                    day.format("%Y-%m-%d"),
                    next.format("%Y-%m-%d"),
                ))
                .await?;
            created += 1;
        }
    }
    Ok(created)
}

/// Drops partitions of every day-partitioned table (findings, alarms,
/// alarm triage history) for days strictly before
/// `cutoff`, but never the partition for the current day; returns how many
/// were dropped.
pub async fn drop_partitions_before(client: &Client, cutoff: NaiveDate) -> Result<u32, StoreError> {
    locked(client, drop_partitions(client, cutoff)).await
}

async fn drop_partitions(client: &Client, cutoff: NaiveDate) -> Result<u32, StoreError> {
    let cutoff = cutoff.min(chrono::Utc::now().date_naive());
    let mut dropped = 0;
    for table in PARTITIONED {
        for day in partition_days_of(client, table).await?.range(..cutoff) {
            client
                .batch_execute(&format!(
                    "DROP TABLE IF EXISTS {}",
                    partition_name(table, *day)
                ))
                .await?;
            dropped += 1;
        }
    }
    Ok(dropped)
}
