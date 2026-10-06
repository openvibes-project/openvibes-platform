//! Alarm suppressions managed by the console (P14), run as the
//! `openvibes-console` role.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use openvibes_core::{Alarm, AlarmProcess, Confidence, Identifier, Severity};
use platform_store::{
    Client,
    alarm_suppressions::{self, Change},
    alarms,
    console_read::AgentScope,
};

const AGENT: &str = "agent.00000000-0000-4000-8000-000000000401";

async fn setup() -> (TestDb, i64) {
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

async fn as_console(db: &TestDb) -> Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    client
}

fn scoped() -> AgentScope {
    AgentScope::AssetGroups(vec!["00000000-0000-4000-8000-00000000000f".into()])
}

#[tokio::test]
async fn suppressions_are_derived_from_the_alarm_and_keep_history() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let now = Utc::now();
    let global = AgentScope::Global;
    let Change::Done(command) = alarm_suppressions::create(
        &mut client,
        &global,
        alarm,
        "command",
        "cron job",
        "alice",
        now,
    )
    .await
    .unwrap() else {
        panic!("expected a suppression");
    };
    assert_eq!(command.exe.as_deref(), Some("/usr/bin/sh"));
    assert_eq!(
        command.args_sha256.as_deref(),
        Some(alarms::args_sha256(&["sh".into(), "-c".into(), "id".into()]).as_str()),
        "the same hash ingest matches on"
    );
    let Change::Done(host) =
        alarm_suppressions::create(&mut client, &global, alarm, "host", "lab box", "alice", now)
            .await
            .unwrap()
    else {
        panic!("expected a suppression");
    };
    assert_eq!(host.agent_id.as_deref(), Some(AGENT));
    assert_eq!(
        alarm_suppressions::list(&client, &global)
            .await
            .unwrap()
            .len(),
        2
    );
    for (kind, note) in [("everywhere", "x"), ("host", " ")] {
        assert_eq!(
            alarm_suppressions::create(&mut client, &global, alarm, kind, note, "alice", now)
                .await
                .unwrap(),
            Change::Invalid
        );
    }
    assert!(matches!(
        alarm_suppressions::remove(&mut client, &global, command.id, "bob", now)
            .await
            .unwrap(),
        Change::Done(_)
    ));
    assert_eq!(
        alarm_suppressions::remove(&mut client, &global, command.id, "bob", now)
            .await
            .unwrap(),
        Change::NotFound,
        "already removed"
    );
    assert_eq!(
        alarm_suppressions::list(&client, &global).await.unwrap(),
        [host]
    );
    let admin = db.pool.get().await.unwrap();
    let kept: i64 = admin
        .query_one(
            "SELECT count(*) FROM alarm_suppressions WHERE removed_by = 'bob'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(kept, 1, "a removed suppression stays as history");
    let audited: i64 = admin
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action LIKE 'alarm.suppression.%'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audited, 3);
    drop((client, admin));
    db.drop().await;
}

#[tokio::test]
async fn a_scoped_caller_cannot_suppress_everywhere_nor_see_it() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let now = Utc::now();
    for kind in ["program", "command"] {
        assert_eq!(
            alarm_suppressions::create(&mut client, &scoped(), alarm, kind, "noisy", "sam", now)
                .await
                .unwrap(),
            Change::NeedsGlobalScope
        );
    }
    // A host suppression on an alarm outside the caller's groups is absent.
    assert_eq!(
        alarm_suppressions::create(&mut client, &scoped(), alarm, "host", "noisy", "sam", now)
            .await
            .unwrap(),
        Change::NotFound
    );
    let Change::Done(program) = alarm_suppressions::create(
        &mut client,
        &AgentScope::Global,
        alarm,
        "program",
        "noisy",
        "alice",
        now,
    )
    .await
    .unwrap() else {
        panic!("expected a suppression");
    };
    assert!(
        alarm_suppressions::list(&client, &scoped())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        alarm_suppressions::remove(&mut client, &scoped(), program.id, "sam", now)
            .await
            .unwrap(),
        Change::NotFound
    );
    drop(client);
    db.drop().await;
}

/// The console's `command` hash and ingest's agree end to end, with args
/// that need escaping: a suppression made from one alarm closes the same
/// command when it is reported again.
#[tokio::test]
async fn a_command_suppression_closes_the_same_command_on_reingest() {
    let (db, _) = setup().await;
    let mut admin = db.pool.get().await.unwrap();
    let now = Utc::now();
    let args = vec![
        "sh".to_owned(),
        "-c".to_owned(),
        "echo \"é\"\tdone".to_owned(),
    ];
    let alarm = |n: u32| Alarm {
        detection: None,
        alarm_id: Identifier::new(format!("alarm.{n:032x}")).unwrap(),
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
        process: AlarmProcess {
            pid: 1,
            exe: "/usr/bin/sh".into(),
            args: args.clone(),
            cwd: None,
            uid: 0,
            euid: 0,
            truncated: false,
            seeded: false,
        },
        ancestors: vec![],
    };
    let partitions = platform_store::partition_days_of(&admin, "alarms")
        .await
        .unwrap();
    let row = |n| {
        alarms::row(
            &alarm(n),
            now - Duration::days(1),
            now + Duration::minutes(5),
            &partitions,
        )
        .unwrap()
    };
    alarms::insert_batch(&mut admin, AGENT, 0, &[row(7)], now)
        .await
        .unwrap();
    let first: i64 = admin
        .query_one(
            "SELECT id FROM alarms WHERE alarm_id = $1",
            &[&format!("alarm.{:032x}", 7)],
        )
        .await
        .unwrap()
        .get(0);
    let mut client = as_console(&db).await;
    let made = alarm_suppressions::create(
        &mut client,
        &AgentScope::Global,
        first,
        "command",
        "ok",
        "a",
        now,
    )
    .await
    .unwrap();
    assert!(matches!(made, Change::Done(_)), "{made:?}");
    let done = alarms::insert_batch(&mut admin, AGENT, 0, &[row(8)], now)
        .await
        .unwrap();
    assert_eq!(done.suppressed, 1, "the re-reported command is closed");
    drop((client, admin));
    db.drop().await;
}
