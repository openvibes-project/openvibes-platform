//! Daily finding partitions, retention, and the status summary.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;

async fn migrated() -> (TestDb, deadpool_postgres::Client) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    (db, client)
}

#[tokio::test]
async fn partitions_are_created_once_and_today_is_never_dropped() {
    let (db, client) = migrated().await;
    let today = Utc::now().date_naive();
    assert_eq!(
        platform_store::ensure_partitions(&client, today, 7)
            .await
            .unwrap(),
        8
    );
    assert_eq!(
        platform_store::ensure_partitions(&client, today, 7)
            .await
            .unwrap(),
        0
    );
    let tomorrow = today + Duration::days(1);
    assert_eq!(
        platform_store::drop_partitions_before(&client, today)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        platform_store::drop_partitions_before(&client, tomorrow)
            .await
            .unwrap(),
        0,
        "a cutoff after today still keeps today's partition"
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn retention_drops_only_older_partitions() {
    let (db, client) = migrated().await;
    let today = Utc::now().date_naive();
    platform_store::ensure_partitions(&client, today - Duration::days(100), 100)
        .await
        .unwrap();
    let cutoff = today - Duration::days(90);
    assert_eq!(
        platform_store::drop_partitions_before(&client, cutoff)
            .await
            .unwrap(),
        10
    );
    let status = platform_store::status(&client, Utc::now()).await.unwrap();
    assert_eq!(status.oldest_partition, Some(cutoff));
    assert_eq!(status.newest_partition, Some(today));
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn status_of_an_empty_database_is_all_zero() {
    let (db, client) = migrated().await;
    let status = platform_store::status(&client, Utc::now()).await.unwrap();
    assert_eq!(status.schema_version, Some(1));
    assert_eq!(
        (
            status.agents_active,
            status.agents_offline,
            status.agents_revoked,
            status.tokens_usable
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(
        (status.oldest_partition, status.newest_partition),
        (None, None)
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn agents_silent_for_fifteen_minutes_are_offline() {
    let (db, client) = migrated().await;
    let now = Utc::now();
    for (index, seen) in [
        (1, now - Duration::minutes(16)),
        (2, now - Duration::minutes(1)),
    ] {
        client
            .execute(
                "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at)
                 VALUES ($1, 'active', $2, $3)",
                &[
                    &format!("agent.00000000-0000-4000-8000-00000000000{index}"),
                    &now,
                    &seen,
                ],
            )
            .await
            .unwrap();
    }
    let status = platform_store::status(&client, now).await.unwrap();
    assert_eq!((status.agents_active, status.agents_offline), (2, 1));
    drop(client);
    db.drop().await;
}
