//! An agent and one of its alarms, for the suppression tests.

use chrono::{Duration, Utc};
use openvibes_core::{Alarm, AlarmProcess, Confidence, Identifier, Severity};
use platform_store::{Client, alarms};

use crate::common::TestDb;

pub const AGENT: &str = "agent.00000000-0000-4000-8000-000000000401";

pub async fn setup() -> (TestDb, i64) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    let now = Utc::now();
    platform_store::ensure_partitions(&admin, now.date_naive() - Duration::days(1), 2)
        .await
        .unwrap();
    admin
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', $2)",
            &[&AGENT, &now],
        )
        .await
        .unwrap();
    let process = |exe: &str| AlarmProcess {
        pid: 1,
        exe: exe.into(),
        args: vec!["sh".into(), "-c".into(), "id".into()],
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
        message: "A web server started a shell".into(),
        first_seen_unix_ms: now.timestamp_millis(),
        last_seen_unix_ms: now.timestamp_millis(),
        count: 1,
        process: process("/usr/bin/sh"),
        ancestors: vec![process("/usr/sbin/nginx")],
    };
    let partitions = platform_store::partition_days_of(&admin, "alarms")
        .await
        .unwrap();
    let row = alarms::row(
        &alarm,
        now - Duration::days(1),
        now + Duration::minutes(5),
        &partitions,
    )
    .unwrap();
    alarms::insert_batch(&mut admin, AGENT, 0, &[row], now)
        .await
        .unwrap();
    let id = admin
        .query_one("SELECT id FROM alarms", &[])
        .await
        .unwrap()
        .get(0);
    (db, id)
}

pub async fn as_console(db: &TestDb) -> Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    client
}
