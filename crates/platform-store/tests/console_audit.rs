//! Audit retention changes use version checks and commit with their audit row.

mod common;

use chrono::Utc;
use common::TestDb;
use platform_store::{
    audit::{
        AuditExportQuery, AuditQuery, cleanup_expired_events, events, export_events, record_export,
        retention_policy, update_retention_policy,
    },
    console_read::PageLimit,
};

#[tokio::test]
async fn retention_updates_are_bounded_versioned_and_transactionally_audited() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();

    let initial = retention_policy(&client).await.unwrap();
    assert_eq!((initial.retention_days, initial.version), (365, 1));
    let updated =
        update_retention_policy(&mut client, 180, initial.version, "operator-1", Utc::now())
            .await
            .unwrap()
            .unwrap();
    assert_eq!((updated.retention_days, updated.version), (180, 2));
    assert_eq!(updated.updated_by, "operator-1");

    assert!(
        update_retention_policy(&mut client, 30, initial.version, "operator-2", Utc::now())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(retention_policy(&client).await.unwrap(), updated);
    assert!(
        update_retention_policy(&mut client, 0, 2, "operator-2", Utc::now())
            .await
            .is_err()
    );

    let audit = client
        .query_one(
            "SELECT action, result, detail->>'retention_days', detail->>'version'
             FROM audit_log WHERE action = 'audit.retention.updated'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(audit.get::<_, &str>(0), "audit.retention.updated");
    assert_eq!(audit.get::<_, &str>(1), "success");
    assert_eq!(audit.get::<_, &str>(2), "180");
    assert_eq!(audit.get::<_, &str>(3), "2");
    assert_eq!(
        client
            .query_one(
                "SELECT count(*) FROM audit_log WHERE action = 'audit.retention.updated'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn audit_event_reads_are_filtered_keyset_paged_and_safe() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let since = Utc::now() - chrono::Duration::seconds(10);
    for (actor, action) in [
        ("alice", "login.success"),
        ("bob", "agent.read"),
        ("alice", "logout"),
    ] {
        client.execute(
            "INSERT INTO audit_log(actor, action, target, result, detail, source_address, user_agent) VALUES ($1,$2,'target','success','{\"secret\":true}'::jsonb,'192.0.2.1','private-agent')",
            &[&actor, &action],
        ).await.unwrap();
    }
    let query = AuditQuery {
        since,
        until: None,
        actor: Some("alice".into()),
        action: None,
        result: Some("success".into()),
        after: None,
        limit: PageLimit::new(1).unwrap(),
    };
    let first = events(&client, &query).await.unwrap();
    assert_eq!(first.items.len(), 1);
    assert!(first.next.is_some());
    let mut second_query = query.clone();
    second_query.after = first.next;
    let second = events(&client, &second_query).await.unwrap();
    assert_eq!(second.items.len(), 1);
    assert!(second.next.is_none());
    assert_eq!(first.items[0].actor, "alice");
    assert!(first.items[0].action == "logout" || first.items[0].action == "login.success");
    let export_query = AuditExportQuery {
        since,
        until: None,
        actor: Some("alice".into()),
        action: None,
        result: Some("success".into()),
    };
    let export = export_events(&client, &export_query).await.unwrap();
    assert!(!export.too_large);
    assert_eq!(export.items.len(), 2);
    record_export(&client, "operator", &export_query, 2, &"a".repeat(64))
        .await
        .unwrap();
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn audit_cleanup_uses_policy_and_deletes_expired_rows() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    let expired = now - chrono::Duration::days(366);
    client
        .execute(
            "INSERT INTO audit_log(at, actor, action, result)
         VALUES ($1, 'operator', 'old', 'success'), ($2, 'operator', 'new', 'success')",
            &[&expired, &now],
        )
        .await
        .unwrap();
    assert_eq!(cleanup_expired_events(&client, now).await.unwrap(), 1);
    let remaining: i64 = client
        .query_one("SELECT count(*) FROM audit_log", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(remaining, 1);
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn audit_export_refuses_row_and_byte_overflows_before_loading_events() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let since = Utc::now() - chrono::Duration::seconds(1);
    client
        .execute(
            "INSERT INTO audit_log(actor, action, result)
             SELECT 'many', 'audit.test', 'success' FROM generate_series(1, 10001)",
            &[],
        )
        .await
        .unwrap();
    let row_overflow = export_events(
        &client,
        &AuditExportQuery {
            since,
            until: None,
            actor: Some("many".into()),
            action: None,
            result: None,
        },
    )
    .await
    .unwrap();
    assert!(row_overflow.too_large);
    assert!(row_overflow.items.is_empty());

    client
        .execute(
            "INSERT INTO audit_log(actor, action, result)
             VALUES (repeat('x', 3 * 1024 * 1024), 'audit.large', 'success')",
            &[],
        )
        .await
        .unwrap();
    let byte_overflow = export_events(
        &client,
        &AuditExportQuery {
            since,
            until: None,
            actor: None,
            action: Some("audit.large".into()),
            result: None,
        },
    )
    .await
    .unwrap();
    assert!(byte_overflow.too_large);
    assert!(byte_overflow.items.is_empty());
    drop(client);
    db.drop().await;
}
