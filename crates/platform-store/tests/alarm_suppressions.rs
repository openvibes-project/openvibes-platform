//! Alarm suppressions managed by the console (P14), run as the
//! `openvibes-console` role.

mod common;
mod suppression_fixture;

use chrono::{Duration, Utc};
use openvibes_core::{Alarm, AlarmProcess, Confidence, Identifier, Severity};
use platform_store::{
    alarm_suppressions::{self, Change, ListFilter, Request, What, Where},
    alarms,
    console_read::AgentScope,
    console_settings,
};
use suppression_fixture::{AGENT, as_console, setup};

fn ask(alarm: i64, what: What, place: Where, reason: &str) -> Request<'_> {
    Request {
        alarm_row_id: alarm,
        what,
        place,
        for_days: None,
        reason,
    }
}

const ALL: ListFilter = ListFilter {
    state: None,
    alarm_id: None,
};

fn scoped() -> AgentScope {
    AgentScope::AssetGroups(vec!["00000000-0000-4000-8000-00000000000f".into()])
}

#[tokio::test]
async fn suppressions_are_derived_from_the_alarm_and_keep_history() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let now = Utc::now();
    let global = AgentScope::Global;
    let request = ask(alarm, What::Command, Where::All, "cron job");
    let Change::Done(command) =
        alarm_suppressions::request(&mut client, &global, &request, "alice", now)
            .await
            .unwrap()
    else {
        panic!("expected a suppression");
    };
    assert_eq!(command.exe.as_deref(), Some("/usr/bin/sh"));
    assert_eq!(
        command.args_sha256.as_deref(),
        Some(alarms::args_sha256(&["sh".into(), "-c".into(), "id".into()]).as_str()),
        "the same hash ingest matches on"
    );
    let request = ask(alarm, What::Program, Where::Host, "lab box");
    let Change::Done(host) =
        alarm_suppressions::request(&mut client, &global, &request, "alice", now)
            .await
            .unwrap()
    else {
        panic!("expected a suppression");
    };
    assert_eq!(host.agent_id.as_deref(), Some(AGENT));
    assert_eq!(host.scope, "program");
    let listed = alarm_suppressions::list(&client, &global, &ALL, now).await;
    assert_eq!(listed.unwrap().len(), 2);
    let blank = ask(alarm, What::Program, Where::Host, " ");
    let fortnight = Request {
        for_days: Some(14),
        ..ask(alarm, What::Program, Where::Host, "x")
    };
    for (request, field) in [(blank, "reason"), (fortnight, "for")] {
        assert_eq!(
            alarm_suppressions::request(&mut client, &global, &request, "alice", now)
                .await
                .unwrap(),
            Change::Invalid(field.into())
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
    let listed = alarm_suppressions::list(&client, &global, &ALL, now).await;
    assert_eq!(listed.unwrap(), [host]);
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

/// All hosts needs a caller reaching all hosts to make or remove it, but
/// every reader sees it (ruling 5): it closes alarms on their hosts too.
#[tokio::test]
async fn a_scoped_caller_cannot_suppress_everywhere_but_sees_it() {
    let (db, alarm) = setup().await;
    let mut client = as_console(&db).await;
    let now = Utc::now();
    for what in [What::Program, What::Command] {
        let request = ask(alarm, what, Where::All, "noisy");
        assert_eq!(
            alarm_suppressions::request(&mut client, &scoped(), &request, "sam", now)
                .await
                .unwrap(),
            Change::NeedsGlobalScope
        );
    }
    // A host suppression on an alarm outside the caller's groups is absent.
    let request = ask(alarm, What::Program, Where::Host, "noisy");
    assert_eq!(
        alarm_suppressions::request(&mut client, &scoped(), &request, "sam", now)
            .await
            .unwrap(),
        Change::NotFound
    );
    let request = ask(alarm, What::Program, Where::All, "noisy");
    let Change::Done(program) =
        alarm_suppressions::request(&mut client, &AgentScope::Global, &request, "alice", now)
            .await
            .unwrap()
    else {
        panic!("expected a suppression");
    };
    let listed = alarm_suppressions::list(&client, &scoped(), &ALL, now).await;
    let ids: Vec<i64> = listed.unwrap().iter().map(|s| s.id).collect();
    assert_eq!(ids, [program.id]);
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
    let request = ask(first, What::Command, Where::All, "ok");
    let made = alarm_suppressions::request(&mut client, &AgentScope::Global, &request, "a", now)
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

/// Signature rows (device rule sets, every device) are global-only, even
/// though they name no host, group or device.
#[tokio::test]
async fn a_signature_row_is_read_by_global_readers_only() {
    let (db, _) = setup().await;
    let admin = db.pool.get().await.unwrap();
    admin
        .execute(
            "INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, note, created_by,
                created_at, state, activated_at)
             VALUES ('device-unifi', 'ips.1', 'signature', 'n', 't', now(), 'active', now())",
            &[],
        )
        .await
        .unwrap();
    let client = as_console(&db).await;
    let now = Utc::now();
    let scoped_list = alarm_suppressions::list(&client, &scoped(), &ALL, now).await;
    assert!(scoped_list.unwrap().is_empty());
    let global_list = alarm_suppressions::list(&client, &AgentScope::Global, &ALL, now).await;
    assert_eq!(global_list.unwrap()[0].scope, "signature");
    drop((client, admin));
    db.drop().await;
}

/// Decide and remove use the caller's reach: an all-hosts row needs a
/// global caller, a group row a caller holding that group.
#[tokio::test]
async fn decide_and_remove_follow_reach() {
    let (db, alarm) = setup().await;
    let mut admin = db.pool.get().await.unwrap();
    let mine = common::manual_group(&admin, "mine", &[AGENT]).await;
    let other = common::manual_group(&admin, "other", &[]).await;
    let approval = serde_json::json!(true);
    let key = "suppressions.require_approval";
    console_settings::set(&mut admin, key, &approval, "admin", Utc::now())
        .await
        .unwrap();
    let mut client = as_console(&db).await;
    let now = Utc::now();
    let global = AgentScope::Global;
    let mut ask_for = async |place: Where| {
        let request = ask(alarm, What::Program, place, "noisy");
        match alarm_suppressions::request(&mut client, &global, &request, "alice", now).await {
            Ok(Change::Done(made)) => made.id,
            other => panic!("{other:?}"),
        }
    };
    let all = ask_for(Where::All).await;
    let theirs = ask_for(Where::Group(other)).await;
    let ours = ask_for(Where::Group(mine.clone())).await;
    let lead = AgentScope::AssetGroups(vec![mine]);
    for id in [all, theirs] {
        let change = alarm_suppressions::decide(&mut client, &lead, id, true, None, "bob", now);
        assert_eq!(change.await.unwrap(), Change::NotFound, "{id}");
    }
    let change = alarm_suppressions::decide(&mut client, &lead, ours, true, None, "bob", now);
    assert!(matches!(change.await.unwrap(), Change::Done(_)));
    let change = alarm_suppressions::decide(&mut client, &global, all, true, None, "bob", now);
    assert!(matches!(change.await.unwrap(), Change::Done(_)));
    let change = alarm_suppressions::remove(&mut client, &lead, all, "bob", now);
    assert_eq!(change.await.unwrap(), Change::NotFound);
    drop((client, admin));
    db.drop().await;
}

/// A deleted group's waiting request cannot be approved: it would match
/// nothing.
#[tokio::test]
async fn approving_a_request_for_a_deleted_group_is_refused() {
    let (db, alarm) = setup().await;
    let mut admin = db.pool.get().await.unwrap();
    let group = common::manual_group(&admin, "gone", &[]).await;
    let approval = serde_json::json!(true);
    let key = "suppressions.require_approval";
    console_settings::set(&mut admin, key, &approval, "admin", Utc::now())
        .await
        .unwrap();
    let mut client = as_console(&db).await;
    let now = Utc::now();
    let global = AgentScope::Global;
    let request = ask(alarm, What::Program, Where::Group(group.clone()), "noisy");
    let Change::Done(made) =
        alarm_suppressions::request(&mut client, &global, &request, "alice", now)
            .await
            .unwrap()
    else {
        panic!("expected a request");
    };
    admin
        .execute(
            "DELETE FROM console_asset_groups WHERE asset_group_id = $1::text::uuid",
            &[&group],
        )
        .await
        .unwrap();
    let change = alarm_suppressions::decide(&mut client, &global, made.id, true, None, "bob", now);
    assert_eq!(change.await.unwrap(), Change::Invalid("group".into()));
    drop((client, admin));
    db.drop().await;
}
