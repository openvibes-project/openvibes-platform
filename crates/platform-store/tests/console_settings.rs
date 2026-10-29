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

/// The real roles, not the superuser: the console writes a secret and cannot
/// read it back, the vulnerability service reads it and cannot write it.
#[tokio::test]
async fn the_roles_can_do_exactly_what_the_grants_say() {
    let (db, mut client) = common::migrated().await;
    let now = chrono::Utc::now();
    let key = "vulns.nvd_api_key";
    use serde_json::json;

    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    // set, replace, and the other settings calls the console makes
    console_settings::set_secret(&mut client, key, Some("first-key"), "admin-1", now)
        .await
        .unwrap();
    console_settings::set_secret(&mut client, key, Some("second-key"), "admin-2", now)
        .await
        .unwrap();
    let set = console_settings::secrets_set(&client).await.unwrap();
    assert_eq!((set.len(), set[0].changed_by.as_str()), (1, "admin-2"));
    console_settings::set(
        &mut client,
        "vulns.proxy_url",
        &json!("http://p:1"),
        "admin-1",
        now,
    )
    .await
    .unwrap();
    let old = console_settings::reset(&mut client, "vulns.proxy_url", "admin-1", now)
        .await
        .unwrap();
    assert_eq!(old, Some(json!("http://p:1")));
    // the value is not readable by the console's role, however it asks
    for sql in [
        "SELECT value FROM service_secrets",
        "SELECT * FROM service_secrets",
        "SELECT count(*) FROM service_secrets WHERE value = 'second-key'",
    ] {
        let error = client.query(sql, &[]).await.unwrap_err();
        let said = error
            .as_db_error()
            .map_or_else(String::new, |e| e.message().to_owned());
        assert!(said.contains("permission denied"), "{sql}: {error:?}");
    }
    assert!(console_settings::secret(&client, key).await.is_err());
    client.batch_execute("RESET ROLE").await.unwrap();

    console_settings::set(
        &mut client,
        "vulns.check_interval_minutes",
        &json!(30),
        "a",
        now,
    )
    .await
    .unwrap();
    client
        .batch_execute("SET ROLE \"openvibes-vulns\"")
        .await
        .unwrap();
    assert_eq!(
        console_settings::secret(&client, key)
            .await
            .unwrap()
            .as_deref(),
        Some("second-key")
    );
    assert_eq!(
        console_settings::values(&client).await.unwrap()["vulns.check_interval_minutes"],
        json!(30)
    );
    assert!(
        console_settings::set_secret(&mut client, key, Some("x"), "a", now)
            .await
            .is_err()
    );
    client.batch_execute("RESET ROLE").await.unwrap();

    // ingest and distribution read the settings, never a secret
    for role in ["openvibes-ingest", "openvibes-distribution"] {
        client
            .batch_execute(&format!("SET ROLE \"{role}\""))
            .await
            .unwrap();
        assert_eq!(
            console_settings::values(&client).await.unwrap()["vulns.check_interval_minutes"],
            json!(30),
            "{role}"
        );
        assert!(
            console_settings::secret(&client, key).await.is_err(),
            "{role}"
        );
        client.batch_execute("RESET ROLE").await.unwrap();
    }

    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    console_settings::set_secret(&mut client, key, None, "admin-1", now)
        .await
        .unwrap();
    client.batch_execute("RESET ROLE").await.unwrap();
    assert_eq!(console_settings::secret(&client, key).await.unwrap(), None);
    db.drop().await;
}

/// The assistant's key is the one secret the console itself uses, so it lives
/// where the console role can read it and no other service role can.
#[tokio::test]
async fn the_assistant_key_is_readable_by_the_console_only() {
    let (db, mut client) = common::migrated().await;
    let now = chrono::Utc::now();
    let key = "assistant.backend.api_key";

    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    console_settings::set_secret(&mut client, key, Some("model-key-1"), "admin-1", now)
        .await
        .unwrap();
    console_settings::set_secret(&mut client, key, Some("model-key-2"), "admin-2", now)
        .await
        .unwrap();
    assert_eq!(
        console_settings::secret(&client, key)
            .await
            .unwrap()
            .as_deref(),
        Some("model-key-2")
    );
    let set = console_settings::secrets_set(&client).await.unwrap();
    assert_eq!(
        set.iter()
            .map(|s| (s.key.as_str(), s.changed_by.as_str()))
            .collect::<Vec<_>>(),
        [(key, "admin-2")]
    );
    client.batch_execute("RESET ROLE").await.unwrap();

    for role in [
        "openvibes-vulns",
        "openvibes-ingest",
        "openvibes-distribution",
        "openvibes-fetch",
        "openvibes-netlog",
        "openvibes-signer",
    ] {
        client
            .batch_execute(&format!("SET ROLE \"{role}\""))
            .await
            .unwrap();
        assert!(
            console_settings::secret(&client, key).await.is_err(),
            "{role}"
        );
        client.batch_execute("RESET ROLE").await.unwrap();
    }

    // the audit line says set or not set, never the value
    let audit: serde_json::Value = client
        .query_one(
            "SELECT detail FROM audit_log WHERE action = 'settings.changed' ORDER BY id DESC LIMIT 1",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audit["new"], serde_json::json!("set"));
    assert!(!audit.to_string().contains("model-key"));

    client
        .batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    console_settings::set_secret(&mut client, key, None, "admin-1", now)
        .await
        .unwrap();
    assert_eq!(console_settings::secret(&client, key).await.unwrap(), None);
    client.batch_execute("RESET ROLE").await.unwrap();
    db.drop().await;
}
