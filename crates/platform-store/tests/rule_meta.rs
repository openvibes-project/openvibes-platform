//! The rule-metadata index (schema 59): rows per stored bundle, the
//! fallback when a rule is not indexed, the backfill's work list, and the
//! console's grants.

mod common;

use common::TestDb;
use platform_store::{
    Client,
    rule_meta::{self, RuleMeta, RuleMetaRow},
    rules::{self, NewBundle, Published},
};

async fn setup() -> (TestDb, Client) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    rules::add_trust_key(&mut client, "baseline", "org.rules", [7; 32])
        .await
        .unwrap();
    for version in 1..=3 {
        let stored = rules::publish(
            &mut client,
            &NewBundle {
                rule_set_id: "baseline",
                version,
                envelope: b"{}",
                envelope_sha256: [u8::try_from(version).unwrap(); 32],
                issuer_key_id: "org.rules",
                created_at_ms: 1,
                expires_at_ms: i64::MAX,
                published_by: "test",
            },
        )
        .await
        .unwrap();
        assert_eq!(stored, Published::Stored);
    }
    (db, client)
}

fn row(id: &str) -> RuleMetaRow {
    RuleMetaRow {
        rule_id: id.into(),
        rule_version: 2,
        title: "Web server spawns a shell".into(),
        message: "A web server started a shell".into(),
        explain: Some("A web server rarely starts a shell.".into()),
        check: None,
        attack: vec![
            ("TA0002".into(), Some("T1059.004".into())),
            ("TA0003".into(), None),
            ("TA0004".into(), Some("T1059.004".into())),
        ],
    }
}

#[tokio::test]
async fn bundles_are_indexed_per_rule() {
    let (db, client) = setup().await;
    let console = db.pool.get().await.unwrap();
    console
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    // The console writes and reads the index with its own grants.
    rule_meta::upsert_from_bundle(&console, "baseline", 1, &[row("shell")])
        .await
        .unwrap();
    // Idempotent: a second store of the same bundle changes nothing.
    rule_meta::upsert_from_bundle(&console, "baseline", 1, &[row("shell")])
        .await
        .unwrap();
    let meta = rule_meta::get(&console, "baseline", 1, "shell", 2)
        .await
        .unwrap();
    assert_eq!(
        meta,
        Some(RuleMeta {
            title: "Web server spawns a shell".into(),
            message: "A web server started a shell".into(),
            explain: Some("A web server rarely starts a shell.".into()),
            check: None,
            attack: row("shell").attack,
        })
    );
    // Distinct techniques, for the alarm list's filter.
    let techniques: Vec<String> = client
        .query_one(
            "SELECT techniques FROM console_rule_meta WHERE rule_id = 'shell'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(techniques, ["T1059.004"]);
    db.drop().await;
}

#[tokio::test]
async fn unindexed_rules_fall_back() {
    let (db, client) = setup().await;
    rule_meta::upsert_from_bundle(&client, "baseline", 1, &[row("shell")])
        .await
        .unwrap();
    // Another set version, another rule version, or another rule: no row,
    // so the caller shows the rule's title and message from the bundle.
    for (version, rule, rule_version) in [(2, "shell", 2), (1, "shell", 1), (1, "other", 2)] {
        assert_eq!(
            rule_meta::get(&client, "baseline", version, rule, rule_version)
                .await
                .unwrap(),
            None
        );
    }
    db.drop().await;
}

#[tokio::test]
async fn missing_bundles_lists_only_unindexed_bundles() {
    let (db, client) = setup().await;
    rule_meta::upsert_from_bundle(&client, "baseline", 2, &[row("shell")])
        .await
        .unwrap();
    assert_eq!(
        rule_meta::missing_bundles(&client, 10).await.unwrap(),
        [("baseline".to_owned(), 1), ("baseline".to_owned(), 3)]
    );
    assert_eq!(
        rule_meta::missing_bundles(&client, 1).await.unwrap(),
        [("baseline".to_owned(), 1)]
    );
    db.drop().await;
}

#[tokio::test]
async fn explain_and_check_are_capped_by_the_table() {
    let (db, client) = setup().await;
    let mut long = row("shell");
    long.check = Some("x".repeat(601));
    assert!(
        rule_meta::upsert_from_bundle(&client, "baseline", 1, &[long])
            .await
            .is_err()
    );
    db.drop().await;
}
