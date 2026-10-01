//! Threat alarms (protocol P14) stored by ingest, run as the
//! `openvibes-ingest` role.

mod common;

use chrono::{DateTime, Duration, Utc};
use common::TestDb;
use openvibes_core::{Alarm, AlarmProcess, Confidence, Identifier, Severity};
use platform_store::{
    Client,
    alarms::{self, Stored, StoredAlarm},
    ingest::{self, Enrolled, IssuedCert},
    tokens::{self, NewToken},
};

async fn setup() -> (TestDb, String) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    platform_store::ensure_partitions(&admin, Utc::now().date_naive() - Duration::days(2), 4)
        .await
        .unwrap();
    let token = tokens::create(
        &admin,
        &NewToken {
            token_sha256: [1; 32],
            label: None,
            created_by: "test".into(),
            expires_at: Utc::now() + Duration::days(1),
            max_uses: 1,
        },
    )
    .await
    .unwrap();
    let mut client = as_ingest(&db).await;
    let Enrolled::New(identity) =
        ingest::enroll(&mut client, &token, [9; 32], Utc::now(), |_: &str| {
            let now = Utc::now();
            Ok(IssuedCert {
                serial: [0x41; 16],
                spki_sha256: [9; 32],
                not_before: now,
                not_after: now + Duration::days(30),
                chain_pem: vec!["LEAF".into()],
            })
        })
        .await
        .unwrap()
    else {
        panic!("expected a new identity");
    };
    (db, identity.agent_id)
}

async fn as_ingest(db: &TestDb) -> Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute("SET ROLE \"openvibes-ingest\"")
        .await
        .unwrap();
    client
}

fn process(exe: &str, args: &[&str]) -> AlarmProcess {
    AlarmProcess {
        pid: 4242,
        exe: exe.into(),
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        cwd: Some("/var/www".into()),
        uid: 48,
        euid: 48,
        truncated: false,
        seeded: false,
    }
}

fn alarm(id: &str, count: u32, first: DateTime<Utc>, last: DateTime<Utc>) -> Alarm {
    Alarm {
        alarm_id: Identifier::new(id).unwrap(),
        rule_set_id: Identifier::new("baseline").unwrap(),
        rule_set_version: 4,
        rule_id: Identifier::new("web-server-spawns-shell").unwrap(),
        rule_version: 1,
        severity: Severity::High,
        confidence: Confidence::new(80).unwrap(),
        message: "A web server started a shell".into(),
        first_seen_unix_ms: first.timestamp_millis(),
        last_seen_unix_ms: last.timestamp_millis(),
        count,
        process: process("/usr/bin/sh", &["sh", "-c", "id"]),
        ancestors: vec![process("/usr/sbin/nginx", &["nginx: worker process"])],
    }
}

async fn row(client: &Client, alarm: &Alarm) -> StoredAlarm {
    let partitions = platform_store::partition_days_of(client, "alarms")
        .await
        .unwrap();
    let now = Utc::now();
    alarms::row(
        alarm,
        now - Duration::days(2),
        now + Duration::minutes(5),
        &partitions,
    )
    .unwrap()
}

/// (count, last_seen, state, note, process exe) of the agent's one alarm.
async fn stored(
    client: &Client,
    agent: &str,
) -> Vec<(i64, DateTime<Utc>, String, Option<String>, String)> {
    client
        .query(
            "SELECT count, last_seen, state, note, process->>'exe' FROM alarms
             WHERE agent_id = $1 ORDER BY id",
            &[&agent],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
        .collect()
}

fn at(ms: i64) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(ms).unwrap()
}

#[tokio::test]
async fn a_resend_raises_count_and_last_seen_and_never_lowers_them() {
    let (db, agent) = setup().await;
    let mut client = as_ingest(&db).await;
    let t0 = at(Utc::now().timestamp_millis() - 60_000);
    let first = alarm("alarm.00000000000000000000000000000001", 1, t0, t0);
    let one = row(&client, &first).await;
    let now = Utc::now();
    assert_eq!(
        alarms::insert_batch(&mut client, &agent, 0, std::slice::from_ref(&one), now)
            .await
            .unwrap(),
        Stored {
            stored: 1,
            raised: 0,
            suppressed: 0
        }
    );
    // The same batch again stores nothing twice.
    assert_eq!(
        alarms::insert_batch(&mut client, &agent, 0, &[one], now)
            .await
            .unwrap(),
        Stored::default()
    );
    // Five starts later, from another process: count and last seen rise,
    // the stored process stays the first delivery's.
    let t1 = t0 + Duration::seconds(30);
    let mut later = alarm("alarm.00000000000000000000000000000001", 5, t0, t1);
    later.process.exe = "/usr/bin/bash".into();
    let raised = row(&client, &later).await;
    assert_eq!(
        alarms::insert_batch(&mut client, &agent, 0, &[raised], now)
            .await
            .unwrap()
            .raised,
        1
    );
    // An older copy lowers nothing.
    let stale = row(
        &client,
        &alarm("alarm.00000000000000000000000000000001", 2, t0, t0),
    )
    .await;
    alarms::insert_batch(&mut client, &agent, 0, &[stale], now)
        .await
        .unwrap();
    let rows = stored(&client, &agent).await;
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].0, rows[0].1), (5, t1));
    assert_eq!(rows[0].4, "/usr/bin/sh");
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn a_changed_first_seen_never_makes_a_second_row() {
    let (db, agent) = setup().await;
    let mut client = as_ingest(&db).await;
    let t0 = at(Utc::now().timestamp_millis() - 60_000);
    let now = Utc::now();
    for first in [t0, t0 - Duration::days(1)] {
        let one = row(
            &client,
            &alarm("alarm.00000000000000000000000000000002", 1, first, t0),
        )
        .await;
        alarms::insert_batch(&mut client, &agent, 0, &[one], now)
            .await
            .unwrap();
    }
    assert_eq!(stored(&client, &agent).await.len(), 1);
    drop(client);
    db.drop().await;
}

#[test]
fn bad_items_are_refused_with_their_reason() {
    let now = Utc::now();
    let partitions = [now.date_naive()].into();
    let check = |first: DateTime<Utc>, last: DateTime<Utc>| {
        alarms::row(
            &alarm("alarm.00000000000000000000000000000003", 1, first, last),
            now - Duration::days(90),
            now + Duration::minutes(5),
            &partitions,
        )
        .map(drop)
    };
    assert_eq!(check(now, now), Ok(()));
    assert_eq!(
        check(now, now + Duration::days(3000)),
        Err("future_observation")
    );
    assert_eq!(
        check(now - Duration::days(91), now),
        Err("retention_expired")
    );
    assert_eq!(check(now - Duration::days(1), now), Err("unstorable"));
}

#[test]
fn the_command_hash_is_over_the_json_array() {
    let joined = alarms::args_sha256(&["a\u{0}b".into()]);
    let split = alarms::args_sha256(&["a".into(), "b".into()]);
    assert_ne!(joined, split);
    // Pinned vector, shared with the console (plan 4): sha256 of `["sh","-c","id"]`.
    assert_eq!(
        alarms::args_sha256(&["sh".into(), "-c".into(), "id".into()]),
        "b20620c162b2bfedcc8566297de5da8e11b92a4437986865e95e3e91ca31ec41"
    );
}

async fn suppress(
    db: &TestDb,
    scope: &str,
    agent: Option<&str>,
    exe: Option<&str>,
    hash: Option<String>,
) -> i64 {
    let admin = db.pool.get().await.unwrap();
    admin
        .query_one(
            "INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, agent_id, exe,
                args_sha256, note, created_by, created_at)
             VALUES ('baseline', 'web-server-spawns-shell', $1, $2, $3, $4, 'noisy', 'alice', now())
             RETURNING id",
            &[&scope, &agent, &exe, &hash],
        )
        .await
        .unwrap()
        .get(0)
}

type Case<'a> = (
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    Option<String>,
    &'a str,
    bool,
);

#[tokio::test]
async fn each_suppression_scope_closes_matching_alarms_only() {
    let (db, agent) = setup().await;
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let t0 = at(now.timestamp_millis() - 60_000);
    let hash = alarms::args_sha256(&["sh".into(), "-c".into(), "id".into()]);
    // (scope, agent, exe, args hash, the alarm's exe, closes it)
    let cases: [Case; 5] = [
        (
            "host",
            Some(agent.as_str()),
            None,
            None,
            "/usr/bin/sh",
            true,
        ),
        (
            "host",
            Some("agent.someone-else"),
            None,
            None,
            "/usr/bin/sh",
            false,
        ),
        (
            "program",
            None,
            Some("/usr/bin/sh"),
            None,
            "/usr/bin/sh",
            true,
        ),
        (
            "program",
            None,
            Some("/usr/bin/sh"),
            None,
            "/usr/bin/dash",
            false,
        ),
        (
            "command",
            None,
            Some("/usr/bin/sh"),
            Some(hash),
            "/usr/bin/sh",
            true,
        ),
    ];
    for (n, (scope, on_agent, exe, hash, alarm_exe, closes)) in cases.into_iter().enumerate() {
        let id = suppress(&db, scope, on_agent, exe, hash).await;
        let mut sent = alarm(&format!("alarm.{:032}", 100 + n), 1, t0, t0);
        sent.process.exe = alarm_exe.into();
        let one = row(&client, &sent).await;
        let done = alarms::insert_batch(&mut client, &agent, 0, &[one], now)
            .await
            .unwrap();
        assert_eq!(done.suppressed, u32::from(closes), "{scope} #{n}");
        let rows = stored(&client, &agent).await;
        let last = rows.last().unwrap();
        if closes {
            assert_eq!(last.2, "false_positive");
            assert_eq!(
                last.3.as_deref(),
                Some(format!("suppressed by #{id}").as_str())
            );
        } else {
            assert_eq!(last.2, "open");
        }
        // One suppression at a time.
        db.pool
            .get()
            .await
            .unwrap()
            .execute(
                "UPDATE alarm_suppressions SET removed_at = now(), removed_by = 'alice'",
                &[],
            )
            .await
            .unwrap();
    }
    // A removed suppression matches nothing.
    let one = row(
        &client,
        &alarm("alarm.00000000000000000000000000000199", 1, t0, t0),
    )
    .await;
    assert_eq!(
        alarms::insert_batch(&mut client, &agent, 0, &[one], now)
            .await
            .unwrap()
            .suppressed,
        0
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn recurrence_reopens_mitigated_and_expired_risk_only() {
    let (db, agent) = setup().await;
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let t0 = at(now.timestamp_millis() - 60_000);
    let cases = [
        ("mitigated", None, "open"),
        ("false_positive", None, "false_positive"),
        ("accepted_risk", Some(now - Duration::hours(1)), "open"),
        (
            "accepted_risk",
            Some(now + Duration::days(30)),
            "accepted_risk",
        ),
    ];
    for (n, (state, until, _)) in cases.iter().enumerate() {
        let id = format!("alarm.{:032}", 300 + n);
        let first = row(&client, &alarm(&id, 1, t0, t0)).await;
        alarms::insert_batch(&mut client, &agent, 0, &[first], now)
            .await
            .unwrap();
        db.pool
            .get()
            .await
            .unwrap()
            .execute(
                "UPDATE alarms SET state = $2, note = 'handled', accepted_until = $3
                 WHERE alarm_id = $1",
                &[&id, state, until],
            )
            .await
            .unwrap();
        let again = row(&client, &alarm(&id, 2, t0, t0 + Duration::seconds(5))).await;
        alarms::insert_batch(&mut client, &agent, 0, &[again], now)
            .await
            .unwrap();
    }
    let rows = stored(&client, &agent).await;
    for (row, (state, until, expected)) in rows.iter().zip(cases) {
        assert_eq!(row.2, expected, "{state} until {until:?}");
    }
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn dropped_total_only_grows() {
    let (db, agent) = setup().await;
    let mut client = as_ingest(&db).await;
    for dropped in [7, 3] {
        alarms::insert_batch(&mut client, &agent, dropped, &[], Utc::now())
            .await
            .unwrap();
    }
    let admin = db.pool.get().await.unwrap();
    let kept: Option<i64> = admin
        .query_one(
            "SELECT alarms_dropped_total FROM agents WHERE agent_id = $1",
            &[&agent],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(kept, Some(7));
    drop((client, admin));
    db.drop().await;
}
