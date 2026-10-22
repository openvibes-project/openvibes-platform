//! Per-hour alarm starts (schema 60): what ingest records for the alarm
//! page's "Last 24 hours" timeline, and maintenance's 7-day pruning.

mod common;

use chrono::{DateTime, Duration, DurationRound, Utc};
use openvibes_core::{Alarm, AlarmProcess, Confidence, Identifier, Severity};
use platform_store::{Client, alarms};

const AGENT: &str = "agent.00000000-0000-4000-8000-000000000501";

async fn setup() -> (common::TestDb, Client) {
    let db = common::TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    platform_store::ensure_partitions(&admin, Utc::now().date_naive() - Duration::days(1), 2)
        .await
        .unwrap();
    admin
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())",
            &[&AGENT],
        )
        .await
        .unwrap();
    (db, admin)
}

async fn report(admin: &mut Client, count: u32, now: DateTime<Utc>) {
    let process = AlarmProcess {
        pid: 1,
        exe: "/usr/bin/sh".into(),
        args: vec!["sh".into()],
        cwd: None,
        uid: 0,
        euid: 0,
        truncated: false,
        seeded: false,
    };
    let alarm = Alarm {
        detection: None,
        alarm_id: Identifier::new(format!("alarm.{:032x}", 1)).unwrap(),
        rule_set_id: Identifier::new("baseline").unwrap(),
        rule_set_version: 1,
        rule_id: Identifier::new("web-server-spawns-shell").unwrap(),
        rule_version: 1,
        severity: Severity::High,
        confidence: Confidence::new(80).unwrap(),
        message: "m".into(),
        first_seen_unix_ms: now.timestamp_millis(),
        last_seen_unix_ms: now.timestamp_millis(),
        count,
        process: process.clone(),
        ancestors: vec![process],
    };
    let partitions = platform_store::partition_days_of(admin, "alarms")
        .await
        .unwrap();
    let row = alarms::row(
        &alarm,
        now - Duration::days(1),
        now + Duration::minutes(5),
        &partitions,
    )
    .unwrap();
    alarms::insert_batch(admin, AGENT, 0, &[row], now)
        .await
        .unwrap();
}

async fn hours(admin: &Client) -> Vec<(DateTime<Utc>, i64)> {
    admin
        .query(
            "SELECT hour, starts FROM alarm_hourly_starts ORDER BY hour",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
}

fn hour(now: DateTime<Utc>) -> DateTime<Utc> {
    now.duration_trunc(Duration::hours(1)).unwrap()
}

#[tokio::test]
async fn a_new_alarm_records_its_count_and_growth_adds_the_difference() {
    let (db, mut admin) = setup().await;
    let now = Utc::now();
    report(&mut admin, 3, now).await;
    assert_eq!(hours(&admin).await, vec![(hour(now), 3)]);
    report(&mut admin, 5, now).await;
    assert_eq!(hours(&admin).await, vec![(hour(now), 5)]);
    db.drop().await;
}

#[tokio::test]
async fn only_count_growth_is_recorded() {
    let (db, mut admin) = setup().await;
    let now = Utc::now();
    report(&mut admin, 5, now).await;
    report(&mut admin, 5, now).await;
    report(&mut admin, 4, now).await;
    assert_eq!(hours(&admin).await, vec![(hour(now), 5)]);
    db.drop().await;
}

#[tokio::test]
async fn near_limit_growth_does_not_overflow_the_hour() {
    let (db, mut admin) = setup().await;
    let now = Utc::now();
    report(&mut admin, 2_000_000_000, now).await;
    report(&mut admin, 4_000_000_000, now).await;
    assert_eq!(hours(&admin).await, vec![(hour(now), 4_000_000_000)]);
    db.drop().await;
}

#[tokio::test]
async fn maintenance_removes_hours_older_than_seven_days() {
    let (db, admin) = setup().await;
    let now = Utc::now();
    for (id, age) in [(1_i64, 8), (2, 6)] {
        admin
            .execute(
                "INSERT INTO alarm_hourly_starts VALUES ($1, $2, 1)",
                &[&id, &(hour(now) - Duration::days(age))],
            )
            .await
            .unwrap();
    }
    assert_eq!(
        platform_store::prune_alarm_hourly(&admin, now)
            .await
            .unwrap(),
        1
    );
    assert_eq!(hours(&admin).await.len(), 1);
    db.drop().await;
}
