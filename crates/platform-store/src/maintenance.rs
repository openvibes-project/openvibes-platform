use std::collections::BTreeSet;

use chrono::{Duration, NaiveDate};
use deadpool_postgres::Client;

use crate::StoreError;

/// Partition names are built only from dates, never from input.
fn partition_name(day: NaiveDate) -> String {
    format!("findings_{}", day.format("%Y%m%d"))
}

/// The days that have a `findings` partition.
pub(crate) async fn partition_days(client: &Client) -> Result<BTreeSet<NaiveDate>, StoreError> {
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
