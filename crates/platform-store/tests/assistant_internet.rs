// crates/platform-store/tests/assistant_internet.rs
mod common;
use chrono::Utc;
use common::TestDb;
use platform_store::assistant_internet::{self, Update};

#[tokio::test]
async fn off_by_default_versioned_and_audited() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let s = assistant_internet::get(&client).await.unwrap();
    assert_eq!((s.level, s.version), (0, 1));
    let up = Update {
        level: 1,
        searxng_url: None,
        internal_domains: vec!["corp.example".into()],
    };
    let s = assistant_internet::update(&mut client, &up, 1, "alex", Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((s.level, s.version), (1, 2));
    assert!(
        assistant_internet::update(&mut client, &up, 1, "alex", Utc::now())
            .await
            .unwrap()
            .is_none(),
        "stale"
    );
    let audit: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'assistant.internet.changed'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audit, 1);
    db.drop().await;
}

#[tokio::test]
async fn level_two_needs_a_searxng_url_and_the_role_reads_only_what_it_needs() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let bad = Update {
        level: 2,
        searxng_url: None,
        internal_domains: vec![],
    };
    assert!(
        assistant_internet::update(&mut client, &bad, 1, "alex", Utc::now())
            .await
            .is_err()
    );
    let grants: Vec<String> = client
        .query(
            "SELECT table_name FROM information_schema.role_table_grants
                WHERE grantee = 'openvibes-fetch' AND privilege_type <> 'SELECT'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert!(grants.is_empty(), "read-only: {grants:?}");
    db.drop().await;
}
