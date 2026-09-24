//! Audit retention changes use version checks and commit with their audit row.

mod common;

use chrono::Utc;
use common::TestDb;
use platform_store::audit::{retention_policy, update_retention_policy};

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
