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

#[tokio::test]
async fn a_setting_goes_back_to_its_default_and_the_change_is_audited() {
    let (db, mut client) = common::migrated().await;
    let now = chrono::Utc::now();
    let key = "vulns.check_interval_minutes";
    assert_eq!(
        console_settings::reset(&mut client, key, "a", now)
            .await
            .unwrap(),
        None
    );
    console_settings::set(&mut client, key, &serde_json::json!(30), "a", now)
        .await
        .unwrap();
    let old = console_settings::reset(&mut client, key, "a", now)
        .await
        .unwrap();
    assert_eq!(old, Some(serde_json::json!(30)));
    assert!(console_settings::values(&client).await.unwrap().is_empty());
    let recent = console_settings::recent(&client, 5).await.unwrap();
    assert_eq!(recent[0].detail["new"], serde_json::Value::Null);
    assert_eq!(recent[0].detail["old"], serde_json::json!(30));
    db.drop().await;
}

#[tokio::test]
async fn a_secret_is_stored_apart_and_its_value_stays_out_of_the_audit_log() {
    let (db, mut client) = common::migrated().await;
    let now = chrono::Utc::now();
    let key = "vulns.nvd_api_key";
    console_settings::set_secret(&mut client, key, Some("s3cret-key"), "admin-1", now)
        .await
        .unwrap();
    assert_eq!(
        console_settings::secret(&client, key)
            .await
            .unwrap()
            .as_deref(),
        Some("s3cret-key")
    );
    let set = console_settings::secrets_set(&client).await.unwrap();
    assert_eq!(
        (set.len(), set[0].key.as_str(), set[0].changed_by.as_str()),
        (1, key, "admin-1")
    );
    assert!(console_settings::values(&client).await.unwrap().is_empty());
    let audit: String = client
        .query_one(
            "SELECT string_agg(detail::text, ' ') FROM audit_log WHERE action = 'settings.changed'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!audit.contains("s3cret-key"), "{audit}");
    assert!(
        audit.contains("\"new\": \"set\"") && audit.contains("\"old\": \"not set\""),
        "{audit}"
    );
    console_settings::set_secret(&mut client, key, None, "admin-1", now)
        .await
        .unwrap();
    assert_eq!(console_settings::secret(&client, key).await.unwrap(), None);
    assert!(
        console_settings::secrets_set(&client)
            .await
            .unwrap()
            .is_empty()
    );
    db.drop().await;
}
