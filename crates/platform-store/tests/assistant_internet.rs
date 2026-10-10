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

#[tokio::test]
async fn denylist_is_lowercase_distinct_and_readable_by_the_fetch_role() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    client
        .batch_execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname)
               VALUES ('agent.00000000-0000-0000-0000-000000000001', 'active', now(), now(), 'Web01.Corp'),
                      ('agent.00000000-0000-0000-0000-000000000002', 'active', now(), now(), '');
             INSERT INTO console_users (user_id, username, display_name, created_at)
               VALUES ('00000000-0000-0000-0000-000000000001', 'alex', 'Alex', now());",
        )
        .await
        .unwrap();
    // A single-label name is allowed.
    let up = Update {
        level: 1,
        searxng_url: None,
        internal_domains: vec![
            "Intranet".to_lowercase(),
            "corp.example".into(),
            "web01.corp".into(),
        ],
    };
    assistant_internet::update(&mut client, &up, 1, "alex", Utc::now())
        .await
        .unwrap()
        .unwrap();

    client
        .batch_execute("SET ROLE \"openvibes-fetch\"")
        .await
        .unwrap();
    let mut got = assistant_internet::denylist(&client).await.unwrap();
    got.sort();
    let mut want: Vec<String> = [
        "agent.00000000-0000-0000-0000-000000000001",
        "agent.00000000-0000-0000-0000-000000000002",
        "web01.corp",
        "web01",
        "alex",
        "intranet",
        "corp.example",
    ]
    .map(String::from)
    .into();
    want.sort();
    assert_eq!(got, want);
    let denied = client
        .execute("UPDATE assistant_internet SET level = 0", &[])
        .await;
    assert!(denied.is_err(), "fetch role must not update");
    client.batch_execute("RESET ROLE").await.unwrap();

    // The console's own role can run the whole write path.
    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    let down = Update {
        level: 0,
        searxng_url: None,
        internal_domains: vec![],
    };
    let s = assistant_internet::update(&mut client, &down, 2, "alex", Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s.version, 3);
    client.batch_execute("RESET ROLE").await.unwrap();
    db.drop().await;
}

#[tokio::test]
async fn denylist_holds_the_short_name_of_every_fqdn() {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    client
        .batch_execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname)
               VALUES ('agent.00000000-0000-0000-0000-000000000001', 'active', now(), now(),
                       'web-01.corp.example')",
        )
        .await
        .unwrap();
    let got = assistant_internet::denylist(&client).await.unwrap();
    for name in ["web-01.corp.example", "web-01"] {
        assert!(got.contains(&name.to_owned()), "{name} missing: {got:?}");
    }
    db.drop().await;
}
