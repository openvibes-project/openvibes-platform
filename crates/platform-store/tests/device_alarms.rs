//! Device alarms: insert, collapse resend, suppressions, reopen, partitions.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use deadpool_postgres::Client;
use platform_store::device_alarms::{self, DeviceAlarm, DeviceStored};

async fn setup() -> (TestDb, i64) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    platform_store::ensure_partitions(&admin, Utc::now().date_naive() - Duration::days(1), 3)
        .await
        .unwrap();
    let id = platform_store::devices::add(
        &admin,
        "r",
        "unifi",
        "192.168.1.1".parse().unwrap(),
        "t",
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    (db, id)
}

async fn as_netlog(db: &TestDb) -> Client {
    let c = db.pool.get().await.unwrap();
    c.batch_execute("SET ROLE \"openvibes-netlog\"")
        .await
        .unwrap();
    c
}

fn alarm(device: i64, count: i64) -> DeviceAlarm {
    let now = Utc::now();
    DeviceAlarm {
        device_id: device,
        alarm_id: "2402000/81.181.129.172/1".into(),
        rule_id: "ips.2402000".into(),
        severity: "medium".into(),
        confidence: 80,
        message: "ET DROP Dshield: blocked".into(),
        first_seen: now,
        last_seen: now,
        count,
        network: serde_json::json!({"src": "81.181.129.172", "action": "blocked"}),
    }
}

#[tokio::test]
async fn a_resend_with_a_higher_count_raises_it() {
    let (db, device) = setup().await;
    let mut c = as_netlog(&db).await;
    let now = Utc::now();
    let first = device_alarms::insert_batch(&mut c, &[alarm(device, 1)], now)
        .await
        .unwrap();
    assert_eq!(
        first,
        DeviceStored {
            stored: 1,
            ..DeviceStored::default()
        }
    );
    let mut later = alarm(device, 5);
    later.last_seen = now + Duration::seconds(30);
    let second = device_alarms::insert_batch(&mut c, &[later], now)
        .await
        .unwrap();
    assert_eq!(second.raised, 1);
    let admin = db.pool.get().await.unwrap();
    let row = admin
        .query_one("SELECT count, source, state FROM alarms", &[])
        .await
        .unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, String>(1),
            row.get::<_, String>(2)
        ),
        (5, "device".into(), "open".into())
    );
    db.drop().await;
}

#[tokio::test]
async fn a_device_suppression_closes_a_new_alarm_once() {
    let (db, device) = setup().await;
    let admin = db.pool.get().await.unwrap();
    for (scope, dev) in [("device", Some(device)), ("signature", None)] {
        admin
            .execute(
                "INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, device_id, note, created_by, created_at)
                 VALUES ('device-unifi', 'ips.2402000', $1, $2, 'n', 't', now())",
                &[&scope, &dev],
            )
            .await
            .unwrap();
    }
    let mut c = as_netlog(&db).await;
    let done = device_alarms::insert_batch(&mut c, &[alarm(device, 1)], Utc::now())
        .await
        .unwrap();
    assert_eq!((done.stored, done.suppressed), (1, 1));
    let state: String = admin
        .query_one("SELECT state FROM alarms", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(state, "false_positive");
    let history: i64 = admin
        .query_one("SELECT count(*) FROM alarm_triage_history", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(history, 1);
    db.drop().await;
}

#[tokio::test]
async fn a_recurrence_reopens_a_mitigated_alarm() {
    let (db, device) = setup().await;
    let admin = db.pool.get().await.unwrap();
    let mut c = as_netlog(&db).await;
    device_alarms::insert_batch(&mut c, &[alarm(device, 1)], Utc::now())
        .await
        .unwrap();
    admin
        .execute("UPDATE alarms SET state = 'mitigated', note = 'fixed'", &[])
        .await
        .unwrap();
    device_alarms::insert_batch(&mut c, &[alarm(device, 2)], Utc::now())
        .await
        .unwrap();
    let state: String = admin
        .query_one("SELECT state FROM alarms", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(state, "open");
    db.drop().await;
}

#[tokio::test]
async fn a_day_without_a_partition_is_skipped_not_fatal() {
    let (db, device) = setup().await;
    let mut c = as_netlog(&db).await;
    let mut old = alarm(device, 1);
    old.first_seen = Utc::now() - Duration::days(30);
    old.alarm_id = "old".into();
    let done = device_alarms::insert_batch(&mut c, &[old, alarm(device, 1)], Utc::now())
        .await
        .unwrap();
    assert_eq!((done.stored, done.unstorable), (1, 1));
    db.drop().await;
}
#[tokio::test]
async fn console_alarm_reads_do_not_see_device_alarms() {
    let (db, device) = setup().await;
    let mut c = as_netlog(&db).await;
    device_alarms::insert_batch(&mut c, &[alarm(device, 1)], Utc::now())
        .await
        .unwrap();
    let admin = db.pool.get().await.unwrap();
    let id: i64 = admin
        .query_one("SELECT id FROM alarms", &[])
        .await
        .unwrap()
        .get(0);
    // The console's alarm list and detail (inner join on agents).
    use platform_store::{console_alarms, console_read::AgentScope};
    let filters = console_alarms::AlarmFilters {
        suppressed: true,
        ..Default::default()
    };
    let page = console_alarms::list(&admin, &AgentScope::Global, &filters, None, 50)
        .await
        .unwrap();
    assert!(page.is_empty());
    assert!(
        console_alarms::detail(&admin, &AgentScope::Global, id)
            .await
            .unwrap()
            .is_none()
    );
    db.drop().await;
}
