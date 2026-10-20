//! General settings: stored per key, audited with the old and new value.

mod common;
use platform_store::console_settings;

#[tokio::test]
async fn a_change_is_stored_and_audited_with_old_and_new() {
    let (db, mut client) = common::migrated().await;
    let now = chrono::Utc::now();
    let key = "suppressions.require_approval";
    let old = console_settings::set(&mut client, key, &serde_json::json!(true), "admin-1", now)
        .await
        .unwrap();
    assert_eq!(old, None);
    let old = console_settings::set(&mut client, key, &serde_json::json!(false), "admin-1", now)
        .await
        .unwrap();
    assert_eq!(old, Some(serde_json::json!(true)));
    let row = client
        .query_one(
            "SELECT detail FROM audit_log WHERE action = 'settings.changed' ORDER BY id DESC LIMIT 1",
            &[],
        )
        .await
        .unwrap();
    let detail: serde_json::Value = row.get(0);
    assert_eq!(
        detail,
        serde_json::json!({"key": key, "old": true, "new": false})
    );
    let all = console_settings::all(&client).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].value, serde_json::json!(false));
    assert_eq!(all[0].changed_by, "admin-1");
    let recent = console_settings::recent(&client, 5).await.unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].detail["new"], serde_json::json!(false));
    db.drop().await;
}

#[tokio::test]
async fn require_approval_is_false_until_set() {
    let (db, mut client) = common::migrated().await;
    assert!(!console_settings::require_approval(&client).await.unwrap());
    let now = chrono::Utc::now();
    console_settings::set(
        &mut client,
        "suppressions.require_approval",
        &serde_json::json!(true),
        "a",
        now,
    )
    .await
    .unwrap();
    assert!(console_settings::require_approval(&client).await.unwrap());
    // a non-bool value counts as off
    console_settings::set(
        &mut client,
        "suppressions.require_approval",
        &serde_json::json!(1),
        "a",
        now,
    )
    .await
    .unwrap();
    assert!(!console_settings::require_approval(&client).await.unwrap());
    db.drop().await;
}
