//! Which suppressions ingest applies (roles spec §8): only active,
//! unexpired ones, on their host or group; the "would have closed" count;
//! deleting a group ends its suppressions (plan ruling 4).

mod common;

use std::sync::atomic::{AtomicU32, Ordering};

use chrono::{DateTime, Duration, SubsecRound, Utc};
use common::groups::Ready as _;
use common::groups::{A1, A2};
use common::{TestDb, manual_group, migrated, rule_group, seed_agent};
use openvibes_core::{Alarm, AlarmProcess, Confidence, Identifier, Severity};
use platform_store::{
    Client,
    alarm_suppressions::{self as store, ListFilter, State},
    alarms,
    console_read::AgentScope,
    host_group_writes,
};

const NOISY: &str = "/usr/bin/noisy";

fn now() -> DateTime<Utc> {
    Utc::now().trunc_subsecs(0)
}

async fn as_role(db: &TestDb, role: &str) -> Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute(&format!("SET ROLE \"{role}\""))
        .await
        .unwrap();
    client
}

async fn fleet() -> (TestDb, Client) {
    let (db, c) = migrated().await;
    seed_agent(&c, A1).await;
    seed_agent(&c, A2).await;
    (db, c)
}

/// An active (or `state`) program suppression of `NOISY` on `agent`,
/// `group` or neither; returns its id.
async fn suppress(
    c: &Client,
    state: &str,
    agent: Option<&str>,
    group: Option<&str>,
    expires_at: Option<DateTime<Utc>>,
) -> i64 {
    let activated = (state != "waiting").then(now);
    let reason = (state == "rejected").then_some("no");
    c.query_one(
        "INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, agent_id, host_group_id,
            exe, note, created_by, created_at, state, activated_at, expires_at, decision_reason)
         VALUES ('baseline', 'web-server-spawns-shell', 'program', $1, $2::text::uuid, $3,
            'noisy', 'alice', now(), $4, $5, $6, $7)
         RETURNING id",
        &[
            &agent,
            &group,
            &NOISY,
            &state,
            &activated,
            &expires_at,
            &reason,
        ],
    )
    .await
    .unwrap()
    .get(0)
}

static NEXT: AtomicU32 = AtomicU32::new(1);

fn process(exe: &str) -> AlarmProcess {
    AlarmProcess {
        pid: 1,
        exe: exe.into(),
        args: vec!["noisy".into(), "--loud".into()],
        cwd: None,
        uid: 0,
        euid: 0,
        truncated: false,
        seeded: false,
    }
}

/// Sends one new `NOISY` alarm from `agent` through ingest; returns its state.
async fn send(client: &mut Client, agent: &str) -> String {
    let at = now();
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let alarm = Alarm {
        detection: None,
        alarm_id: Identifier::new(format!("alarm.{n:032x}")).unwrap(),
        rule_set_id: Identifier::new("baseline").unwrap(),
        rule_set_version: 1,
        rule_id: Identifier::new("web-server-spawns-shell").unwrap(),
        rule_version: 1,
        severity: Severity::High,
        confidence: Confidence::new(80).unwrap(),
        message: "noisy".into(),
        first_seen_unix_ms: at.timestamp_millis(),
        last_seen_unix_ms: at.timestamp_millis(),
        count: 1,
        process: process(NOISY),
        ancestors: vec![],
    };
    let partitions = platform_store::partition_days_of(&*client, "alarms")
        .await
        .unwrap();
    let row = alarms::row(
        &alarm,
        at - Duration::days(1),
        at + Duration::minutes(5),
        &partitions,
    )
    .unwrap();
    alarms::insert_batch(client, agent, 0, &[row], at)
        .await
        .unwrap();
    client
        .query_one(
            "SELECT state FROM alarms WHERE agent_id = $1 AND alarm_id = $2",
            &[&agent, &alarm.alarm_id.as_str()],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn a_group_suppression_follows_membership() {
    let (db, mut c) = fleet().await;
    let group = manual_group(&c, "Noisy", &[A1]).await;
    suppress(&c, "active", None, Some(&group), None).await;
    assert_eq!(send(&mut c, A1).await, "false_positive");
    assert_eq!(send(&mut c, A2).await, "open");
    c.execute(
        "INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
         VALUES ($1::text::uuid, $2, now(), 'test')",
        &[&group, &A2],
    )
    .await
    .unwrap();
    assert_eq!(send(&mut c, A2).await, "false_positive");
    c.execute(
        "DELETE FROM console_host_group_members WHERE agent_id = $1",
        &[&A1],
    )
    .await
    .unwrap();
    assert_eq!(send(&mut c, A1).await, "open");
    db.drop().await;
}

#[tokio::test]
async fn an_expired_suppression_closes_nothing() {
    let (db, mut c) = fleet().await;
    let id = suppress(&c, "active", None, None, Some(now() - Duration::seconds(1))).await;
    assert_eq!(send(&mut c, A1).await, "open");
    c.execute(
        "UPDATE alarm_suppressions SET expires_at = now() + interval '1 hour' WHERE id = $1",
        &[&id],
    )
    .await
    .unwrap();
    assert_eq!(send(&mut c, A1).await, "false_positive");
    db.drop().await;
}

#[tokio::test]
async fn a_waiting_or_rejected_suppression_closes_nothing() {
    let (db, mut c) = fleet().await;
    suppress(&c, "waiting", None, None, None).await;
    suppress(&c, "rejected", None, None, None).await;
    assert_eq!(send(&mut c, A1).await, "open");
    db.drop().await;
}

#[tokio::test]
async fn a_host_where_only_covers_that_host() {
    let (db, mut c) = fleet().await;
    suppress(&c, "active", Some(A1), None, None).await;
    assert_eq!(send(&mut c, A2).await, "open");
    assert_eq!(send(&mut c, A1).await, "false_positive");
    db.drop().await;
}

#[tokio::test]
async fn ingest_role_can_match_groups() {
    let (db, c) = fleet().await;
    let group = manual_group(&c, "Noisy", &[A1]).await;
    suppress(&c, "active", None, Some(&group), None).await;
    let mut ingest = as_role(&db, "openvibes-ingest").await;
    assert_eq!(send(&mut ingest, A1).await, "false_positive");
    db.drop().await;
}

/// A stored `NOISY` alarm from `agent` last seen `days_ago`, with `args`.
async fn seed_seen(c: &Client, agent: &str, days_ago: i64, args: serde_json::Value) {
    let seen = now() - Duration::days(days_ago);
    let process = serde_json::json!({ "exe": NOISY, "args": args });
    c.execute(
        "INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version,
            rule_id, rule_version, severity, confidence, message, first_seen, last_seen, count,
            process, ancestors, received_at, state)
         VALUES (($2 AT TIME ZONE 'UTC')::date, $1, md5(random()::text), 'baseline', 1,
            'web-server-spawns-shell', 1, 'high', 50, 'm', $2, $2, 1, $3, '[]', $2, 'open')",
        &[&agent, &seen, &process],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn would_close_counts_the_last_7_days() {
    let (db, c) = fleet().await;
    platform_store::ensure_partitions(&c, now().date_naive() - Duration::days(9), 11)
        .await
        .unwrap();
    let args = ["noisy", "--loud"];
    for days in [1, 6, 8] {
        seed_seen(&c, A1, days, serde_json::json!(args)).await;
    }
    seed_seen(&c, A1, 1, serde_json::json!(["noisy", "--quiet"])).await;
    // Args that are not a list of strings never count (not hashed as []).
    seed_seen(&c, A1, 1, serde_json::json!("noisy --loud")).await;
    let hash = alarms::args_sha256(&args.map(String::from));
    c.execute(
        "INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, exe, args_sha256, note,
            created_by, created_at, state)
         VALUES ('baseline', 'web-server-spawns-shell', 'command', $1, $2, 'noisy', 'alice',
            now(), 'waiting')",
        &[&NOISY, &hash],
    )
    .await
    .unwrap();
    suppress(&c, "active", None, None, None).await;
    let console = as_role(&db, "openvibes-console").await;
    let rows = store::list(&console, &AgentScope::Global, &ListFilter::default(), now())
        .await
        .unwrap();
    let counts: Vec<_> = rows.iter().map(|s| (s.state, s.would_close)).collect();
    assert_eq!(
        counts,
        [(State::Waiting, Some(2)), (State::Active, None)],
        "{rows:?}"
    );
    db.drop().await;
}

#[tokio::test]
async fn deleting_a_group_ends_its_suppressions() {
    let (db, mut c) = fleet().await;
    let group = manual_group(&c, "Noisy", &[A1]).await;
    let waiting = suppress(&c, "waiting", None, Some(&group), None).await;
    let active = suppress(&c, "active", None, Some(&group), None).await;
    let elsewhere = suppress(&c, "active", Some(A1), None, None).await;
    let preview = host_group_writes::preview(&c, Some(&group), None)
        .await
        .unwrap()
        .ready();
    assert_eq!(preview.suppressions_ended, 2);
    let at = now();
    host_group_writes::delete(&mut c, &group, 1, "ann", at)
        .await
        .unwrap();
    let ended = |id: i64| {
        let c = &c;
        async move {
            let row = c
                .query_one(
                    "SELECT state, decided_by, removed_by FROM alarm_suppressions WHERE id = $1",
                    &[&id],
                )
                .await
                .unwrap();
            let state: String = row.get(0);
            let (decided, removed): (Option<String>, Option<String>) = (row.get(1), row.get(2));
            (state, decided, removed)
        }
    };
    assert_eq!(
        ended(waiting).await,
        ("withdrawn".into(), Some("ann".into()), None)
    );
    assert_eq!(
        ended(active).await,
        ("removed".into(), None, Some("ann".into()))
    );
    assert_eq!(ended(elsewhere).await.0, "active");
    let detail: serde_json::Value = c
        .query_one(
            "SELECT detail->'suppressions_ended' FROM audit_log WHERE action = 'host_group.deleted'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(detail, 2);
    db.drop().await;
}

/// A waiting all-hosts program suppression of `NOISY`.
async fn waiting_program(c: &Client) {
    c.execute(
        "INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, exe, note, created_by,
            created_at, state)
         VALUES ('baseline', 'web-server-spawns-shell', 'program', $1, 'noisy', 'alice', now(),
            'waiting')",
        &[&NOISY],
    )
    .await
    .unwrap();
}

/// (`would_close`, `would_close_capped`) of the one waiting row `read` sees.
async fn counted(db: &TestDb, read: &AgentScope) -> (Option<i64>, bool) {
    let console = as_role(db, "openvibes-console").await;
    let filter = ListFilter {
        state: Some(State::Waiting),
        alarm_id: None,
    };
    let rows = store::list(&console, read, &filter, now()).await.unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    (rows[0].would_close, rows[0].would_close_capped)
}

#[tokio::test]
async fn would_close_counts_only_hosts_the_reader_reaches() {
    let (db, c) = fleet().await;
    let mine = manual_group(&c, "Mine", &[A1]).await;
    seed_seen(&c, A1, 1, serde_json::json!(["noisy"])).await;
    seed_seen(&c, A2, 1, serde_json::json!(["noisy"])).await;
    waiting_program(&c).await;
    assert_eq!(counted(&db, &AgentScope::Global).await, (Some(2), false));
    let scoped = AgentScope::AssetGroups(vec![mine]);
    assert_eq!(counted(&db, &scoped).await, (Some(1), false));
    db.drop().await;
}

#[tokio::test]
async fn would_close_says_when_it_hit_the_cap() {
    let (db, c) = fleet().await;
    let process = serde_json::json!({ "exe": NOISY, "args": ["noisy"] });
    c.execute(
        "INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version,
            rule_id, rule_version, severity, confidence, message, first_seen, last_seen, count,
            process, ancestors, received_at, state)
         SELECT (now() AT TIME ZONE 'UTC')::date, $1, 'alarm.' || n, 'baseline', 1,
            'web-server-spawns-shell', 1, 'high', 50, 'm', now(), now(), 1, $2, '[]', now(), 'open'
         FROM generate_series(1, 10001) n",
        &[&A1, &process],
    )
    .await
    .unwrap();
    waiting_program(&c).await;
    assert_eq!(
        counted(&db, &AgentScope::Global).await,
        (Some(10_000), true)
    );
    db.drop().await;
}

#[tokio::test]
async fn a_rule_group_suppression_matches_and_ends_with_its_group() {
    let (db, mut c) = fleet().await;
    c.batch_execute(&format!(
        "UPDATE agents SET hostname = 'web-01' WHERE agent_id = '{A1}';
         UPDATE agents SET hostname = 'db-01' WHERE agent_id = '{A2}';"
    ))
    .await
    .unwrap();
    let web = rule_group(&c, "Web", &[("hostname", false, &["web-*"])]).await;
    let id = suppress(&c, "active", None, Some(&web), None).await;
    assert_eq!(send(&mut c, A1).await, "false_positive");
    assert_eq!(send(&mut c, A2).await, "open");
    host_group_writes::delete(&mut c, &web, 1, "ann", now())
        .await
        .unwrap();
    let state: String = c
        .query_one("SELECT state FROM alarm_suppressions WHERE id = $1", &[&id])
        .await
        .unwrap()
        .get(0);
    assert_eq!(state, "removed");
    assert_eq!(send(&mut c, A1).await, "open");
    db.drop().await;
}
