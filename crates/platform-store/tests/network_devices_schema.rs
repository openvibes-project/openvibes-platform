//! Schema 46: devices and device alarms.

mod common;

use chrono::Utc;
use common::TestDb;

async fn migrated() -> TestDb {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    platform_store::ensure_partitions(&admin, Utc::now().date_naive(), 1)
        .await
        .unwrap();
    db
}

#[tokio::test]
async fn device_alarm_rows_need_device_fields_and_agent_rows_keep_theirs() {
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    let device: i64 = c
        .query_one(
            "INSERT INTO devices (name, kind, address, created_by, created_at)
             VALUES ('UCG Max', 'unifi', '192.168.1.1', 'test', now()) RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let insert =
        |source: &'static str, agent: Option<&'static str>, dev: Option<i64>, net: bool| {
            let c = &c;
            async move {
                c.execute(
                    "INSERT INTO alarms (first_seen_day, source, agent_id, device_id, alarm_id,
                    rule_set_id, rule_set_version, rule_id, rule_version, severity, confidence,
                    message, first_seen, last_seen, count, process, ancestors, network, received_at)
                 VALUES ((now() AT TIME ZONE 'UTC')::date, $1, $2, $3, 'a1', 'device-unifi', 0,
                    'ips.1', 0, 'medium', 80, 'm', now(), now(), 1,
                    CASE WHEN $2::text IS NULL THEN NULL ELSE '{}'::jsonb END,
                    CASE WHEN $2::text IS NULL THEN NULL ELSE '[]'::jsonb END,
                    CASE WHEN $4 THEN '{}'::jsonb ELSE NULL END, now())",
                    &[&source, &agent, &dev, &net],
                )
                .await
            }
        };
    assert!(insert("device", None, Some(device), true).await.is_ok());
    assert!(
        insert("device", None, None, true).await.is_err(),
        "device row without device_id"
    );
    assert!(
        insert("device", Some("x"), Some(device), true)
            .await
            .is_err(),
        "mixed row"
    );
    assert!(
        insert("agent", None, Some(device), true).await.is_err(),
        "agent row without agent"
    );
    db.drop().await;
}

#[tokio::test]
async fn an_active_address_is_unique_and_a_removed_one_frees_it() {
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    let add = "INSERT INTO devices (name, kind, address, created_by, created_at)
               VALUES ('r', 'unifi', '192.168.1.1', 't', now())";
    c.execute(add, &[]).await.unwrap();
    assert!(c.execute(add, &[]).await.is_err());
    c.execute(
        "UPDATE devices SET removed_at = now(), removed_by = 't'",
        &[],
    )
    .await
    .unwrap();
    c.execute(add, &[]).await.unwrap();
    db.drop().await;
}

#[tokio::test]
async fn the_netlog_role_reads_devices_and_writes_only_counters() {
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    c.execute(
        "INSERT INTO devices (name, kind, address, created_by, created_at)
         VALUES ('r', 'unifi', '192.168.1.1', 't', now())",
        &[],
    )
    .await
    .unwrap();
    c.batch_execute("SET ROLE \"openvibes-netlog\"")
        .await
        .unwrap();
    c.query(
        "SELECT id, address FROM devices WHERE removed_at IS NULL",
        &[],
    )
    .await
    .unwrap();
    c.execute(
        "UPDATE devices SET received = received + 1, last_seen = now()",
        &[],
    )
    .await
    .unwrap();
    assert!(
        c.execute("UPDATE devices SET name = 'x'", &[])
            .await
            .is_err()
    );
    assert!(c.execute("DELETE FROM devices", &[]).await.is_err());
    c.query("SELECT 1 FROM schema_version", &[]).await.unwrap();
    db.drop().await;
}

#[tokio::test]
async fn device_and_signature_suppressions_are_device_rule_sets_only() {
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    let device: i64 = c
        .query_one(
            "INSERT INTO devices (name, kind, address, created_by, created_at)
             VALUES ('r', 'unifi', '192.168.1.1', 't', now()) RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let sup = |set: &'static str, scope: &'static str, dev: Option<i64>| {
        let c = &c;
        async move {
            c.execute(
                "INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, device_id, note,
                    created_by, created_at) VALUES ($1, 'ips.1', $2, $3, 'n', 't', now())",
                &[&set, &scope, &dev],
            )
            .await
        }
    };
    assert!(sup("device-unifi", "device", Some(device)).await.is_ok());
    assert!(sup("device-unifi", "signature", None).await.is_ok());
    assert!(sup("device-unifi", "device", None).await.is_err());
    assert!(sup("baseline-alarms", "signature", None).await.is_err());
    db.drop().await;
}

#[tokio::test]
async fn the_netlog_role_cannot_read_or_rewrite_agent_alarm_details() {
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    c.batch_execute("SET ROLE \"openvibes-netlog\"")
        .await
        .unwrap();
    // What its lookup and update need.
    c.query(
        "SELECT id, first_seen_day, count, last_seen, state, accepted_until FROM alarms
         WHERE device_id = 1 AND alarm_id = 'x'",
        &[],
    )
    .await
    .unwrap();
    // An agent's process (command lines), notes and assignee are not its business.
    for column in [
        "process",
        "ancestors",
        "note",
        "assigned_to",
        "agent_id",
        "detection",
    ] {
        let sql = format!("SELECT {column} FROM alarms LIMIT 1");
        assert!(
            c.query(&sql, &[]).await.is_err(),
            "netlog reads alarms.{column}"
        );
    }
    assert!(
        c.execute("UPDATE alarms SET message = 'x'", &[])
            .await
            .is_err()
    );
    assert!(
        c.execute("UPDATE alarms SET process = '{}'", &[])
            .await
            .is_err()
    );
    db.drop().await;
}
