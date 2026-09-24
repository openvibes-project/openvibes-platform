use std::collections::BTreeSet;

use chrono::{Duration, NaiveDate};
use deadpool_postgres::Client;

use crate::StoreError;

/// Partition names are built only from dates, never from input.
fn partition_name(day: NaiveDate) -> String {
    format!("findings_{}", day.format("%Y%m%d"))
}

/// The days that have a `findings` partition.
pub async fn partition_days(client: &Client) -> Result<BTreeSet<NaiveDate>, StoreError> {
    let rows = client
        .query(
            "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
             WHERE i.inhparent = 'findings'::regclass",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let name: String = row.get(0);
            NaiveDate::parse_from_str(name.strip_prefix("findings_")?, "%Y%m%d").ok()
        })
        .collect())
}

/// Creates daily partitions for `today` and the `days_ahead` days after it
/// that do not exist yet; returns how many were created.
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
    let existing = partition_days(client).await?;
    let mut created = 0;
    for offset in 0..=i64::from(days_ahead) {
        let day = today + Duration::days(offset);
        if existing.contains(&day) {
            continue;
        }
        let next = day + Duration::days(1);
        client
            .batch_execute(&format!(
                "CREATE TABLE IF NOT EXISTS {} PARTITION OF findings
                 FOR VALUES FROM ('{}') TO ('{}')",
                partition_name(day),
                day.format("%Y-%m-%d"),
                next.format("%Y-%m-%d"),
            ))
            .await?;
        created += 1;
    }
    Ok(created)
}

/// Drops partitions for days strictly before `cutoff`, but never the
/// partition for the current day; returns how many were dropped.
pub async fn drop_partitions_before(client: &Client, cutoff: NaiveDate) -> Result<u32, StoreError> {
    locked(client, drop_partitions(client, cutoff)).await
}

async fn drop_partitions(client: &Client, cutoff: NaiveDate) -> Result<u32, StoreError> {
    let cutoff = cutoff.min(chrono::Utc::now().date_naive());
    let mut dropped = 0;
    for day in partition_days(client).await?.range(..cutoff) {
        client
            .batch_execute(&format!("DROP TABLE IF EXISTS {}", partition_name(*day)))
            .await?;
        dropped += 1;
    }
    Ok(dropped)
}
