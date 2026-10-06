//! Console reads and triage of threat alarms (P14), run as the
//! `openvibes-console` role.

mod common;

use chrono::{DateTime, Duration, Utc};
use common::TestDb;
use openvibes_core::{Alarm, AlarmProcess, Confidence, Identifier, Severity};
use platform_store::{
    Client,
    alarms::{self},
    console_alarms::{self, AlarmFilters, TriageChange, TriageOutcome},
    console_read::AgentScope,
};

const AGENT: &str = "agent.00000000-0000-4000-8000-000000000001";

fn alarm(n: u32, rule: &str, at: DateTime<Utc>) -> Alarm {
    let process = |exe: &str| AlarmProcess {
        pid: 1,
        exe: exe.into(),
        args: vec!["sh".into()],
        cwd: None,
        uid: 0,
        euid: 0,
        truncated: false,
        seeded: false,
    };
    Alarm {
        detection: None,
        alarm_id: Identifier::new(format!("alarm.{n:032x}")).unwrap(),
        rule_set_id: Identifier::new("baseline").unwrap(),
        rule_set_version: 1,
        rule_id: Identifier::new(rule).unwrap(),
        rule_version: 1,
        severity: Severity::High,
        confidence: Confidence::new(80).unwrap(),
        message: "A web server started a shell".into(),
        first_seen_unix_ms: at.timestamp_millis(),
        last_seen_unix_ms: at.timestamp_millis(),
        count: 1,
        process: process("/usr/bin/sh"),
        ancestors: vec![process("/usr/sbin/nginx")],
    }
}

/// Three alarms a second apart (newest last), one of them suppressed.
async fn setup() -> (TestDb, Vec<i64>) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    let now = Utc::now();
    platform_store::ensure_partitions(&admin, now.date_naive() - Duration::days(1), 2)
        .await
        .unwrap();
    admin
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname)
             VALUES ($1, 'active', $2, 'web-01')",
            &[&AGENT, &now],
        )
        .await
        .unwrap();
    admin
        .execute(
            "INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, exe, note,
                created_by, created_at)
             VALUES ('baseline', 'quiet-rule', 'program', '/usr/bin/sh', 'noisy', 'a', now())",
            &[],
        )
        .await
        .unwrap();
    let partitions = platform_store::partition_days_of(&admin, "alarms")
        .await
        .unwrap();
    let rows: Vec<_> = [
        (1, "web-server-spawns-shell"),
        (2, "quiet-rule"),
        (3, "other-rule"),
    ]
    .into_iter()
    .map(|(n, rule)| {
        let at = now - Duration::seconds(10 - i64::from(n));
        alarms::row(
            &alarm(n, rule, at),
            now - Duration::days(1),
            now,
            &partitions,
        )
        .unwrap()
    })
    .collect();
    alarms::insert_batch(&mut admin, AGENT, 0, &rows, now)
        .await
        .unwrap();
    let ids = admin
        .query("SELECT id FROM alarms ORDER BY id", &[])
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    (db, ids)
}

async fn as_console(db: &TestDb) -> Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    client
}

#[tokio::test]
async fn the_list_is_newest_first_scoped_filtered_and_paged() {
    let (db, ids) = setup().await;
    let client = as_console(&db).await;
    let all = AlarmFilters::default();
    let page = console_alarms::list(&client, &AgentScope::Global, &all, None, 10)
        .await
        .unwrap();
    assert_eq!(
        page.iter().map(|a| a.id).collect::<Vec<_>>(),
        [ids[2], ids[0]],
        "newest first; the suppressed one hidden by default"
    );
    assert_eq!(page[0].hostname.as_deref(), Some("web-01"));
    assert_eq!(page[0].parent_exe.as_deref(), Some("/usr/sbin/nginx"));
    let with_suppressed = AlarmFilters {
        suppressed: true,
        ..AlarmFilters::default()
    };
    let first = console_alarms::list(&client, &AgentScope::Global, &with_suppressed, None, 2)
        .await
        .unwrap();
    let cursor = first.last().map(|a| (a.last_seen, a.id));
    let second = console_alarms::list(&client, &AgentScope::Global, &with_suppressed, cursor, 2)
        .await
        .unwrap();
    assert_eq!(
        first
            .iter()
            .chain(&second)
            .map(|a| a.id)
            .collect::<Vec<_>>(),
        [ids[2], ids[1], ids[0]]
    );
    let by_rule = AlarmFilters {
        rule_id: Some("other-rule".into()),
        ..AlarmFilters::default()
    };
    assert_eq!(
        console_alarms::list(&client, &AgentScope::Global, &by_rule, None, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    // `active` is open or investigating: the suppressed (false positive)
    // alarm is not active even with suppressed shown.
    let active = AlarmFilters {
        state: Some("active".into()),
        suppressed: true,
        ..AlarmFilters::default()
    };
    assert_eq!(
        console_alarms::list(&client, &AgentScope::Global, &active, None, 10)
            .await
            .unwrap()
            .len(),
        2
    );
    let nobody = AgentScope::AssetGroups(vec!["00000000-0000-4000-8000-00000000000f".into()]);
    assert!(
        console_alarms::list(&client, &nobody, &all, None, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        console_alarms::detail(&client, &nobody, ids[0])
            .await
            .unwrap()
            .is_none()
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn the_detail_carries_the_tree_and_triage() {
    let (db, ids) = setup().await;
    let client = as_console(&db).await;
    let detail = console_alarms::detail(&client, &AgentScope::Global, ids[1])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail.process["exe"], "/usr/bin/sh");
    assert_eq!(detail.ancestors[0]["exe"], "/usr/sbin/nginx");
    assert_eq!(detail.triage.state, "false_positive");
    assert_eq!(detail.triage.updated_by.as_deref(), Some("ingest"));
    assert!(detail.summary.suppressed_by.is_some());
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn triage_follows_the_findings_workflow_with_versions_and_history() {
    let (db, ids) = setup().await;
    let mut client = as_console(&db).await;
    let now = Utc::now();
    let change = |version, state| TriageChange {
        expected_version: version,
        state,
        assigned_to_username: None,
        note: None,
        accepted_until: None,
    };
    let global = AgentScope::Global;
    let update = console_alarms::update_triage;
    assert_eq!(
        update(
            &mut client,
            &global,
            ids[0],
            &change(1, "mitigated"),
            "alice",
            now
        )
        .await
        .unwrap(),
        TriageOutcome::InvalidFields,
        "a completed state needs a note"
    );
    let with_note = TriageChange {
        note: Some("fixed"),
        ..change(1, "mitigated")
    };
    assert_eq!(
        update(&mut client, &global, ids[0], &with_note, "alice", now)
            .await
            .unwrap(),
        TriageOutcome::InvalidTransition,
        "open goes to investigating first"
    );
    let TriageOutcome::Updated(triage) = update(
        &mut client,
        &global,
        ids[0],
        &change(1, "investigating"),
        "alice",
        now,
    )
    .await
    .unwrap() else {
        panic!("expected an update");
    };
    assert_eq!(triage.version, 2);
    assert_eq!(
        update(
            &mut client,
            &global,
            ids[0],
            &change(1, "investigating"),
            "bob",
            now
        )
        .await
        .unwrap(),
        TriageOutcome::Stale
    );
    let nobody = AgentScope::AssetGroups(vec!["00000000-0000-4000-8000-00000000000f".into()]);
    assert_eq!(
        update(
            &mut client,
            &nobody,
            ids[0],
            &change(2, "investigating"),
            "eve",
            now
        )
        .await
        .unwrap(),
        TriageOutcome::NotFound
    );
    let history: i64 = client
        .query_one(
            "SELECT count(*) FROM alarm_triage_history WHERE alarm_row_id = $1",
            &[&ids[0]],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(history, 1);
    let audited: i64 = db
        .pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'alarm.triage.changed'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audited, 1);
    drop(client);
    db.drop().await;
}
