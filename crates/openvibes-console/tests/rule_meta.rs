//! The rule-metadata index from verified bundles: title, message, ATT&CK,
//! and the `explain`/`check` text read from the verified payload; an
//! unverifiable bundle is not indexed; the start-up backfill runs once.

mod common;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use common::http::TestDb;
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{ResourceLimits, SignedRuleEnvelope};
use platform_store::{Client, rule_meta};
use serde_json::json;
use sha2::{Digest, Sha256};

const TRUSTED: [u8; 32] = [21; 32];

/// Stores `baseline` v`version`, signed by `key`, without indexing it.
async fn store(client: &mut Client, version: i64, key: [u8; 32]) {
    let rule = json!({"id":"web-server-spawns-shell","version":3,"title":"Web server spawns a shell",
        "severity":"high","confidence":80,"expression":"event['process.exe'] == '/usr/bin/sh'",
        "finding_message":"A web server started a shell","kind":"process_event",
        "attack":[{"tactic":"TA0002","technique":"T1059.004"},{"tactic":"TA0003"}],
        "explain":"é".repeat(700),"check":"Look at the parent web server's requests."});
    let plain = json!({"id":"plain","version":1,"title":"Plain rule","severity":"low",
        "confidence":50,"expression":"facts['process.count'] >= 1","finding_message":"Plain",
        "kind":"snapshot"});
    let payload = json!({"schema_version":1,"rules":[rule, plain]}).to_string();
    let digest: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
    let now = Utc::now().timestamp_millis();
    let mut envelope: SignedRuleEnvelope = serde_json::from_value(json!({"schema_version":1,
        "rule_set_id":"baseline","rule_set_version":version,"issuer_key_id":"test-key",
        "created_at_unix_ms":now - 86_400_000,"expires_at_unix_ms":now + 86_400_000,
        "payload_encoding":"json","payload_sha256_hex":openvibes_core::hex(&digest),
        "payload":payload,"signature_base64url":""}))
    .unwrap();
    let preimage = openvibes_rules::signing_preimage(&envelope, ResourceLimits::V1).unwrap();
    envelope.signature_base64url =
        URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&key).sign(&preimage).to_bytes());
    let bytes = serde_json::to_vec(&envelope).unwrap();
    platform_store::rules::publish(
        client,
        &platform_store::rules::NewBundle {
            rule_set_id: "baseline",
            version,
            envelope: &bytes,
            envelope_sha256: Sha256::digest(&bytes).into(),
            issuer_key_id: "test-key",
            created_at_ms: envelope.created_at_unix_ms,
            expires_at_ms: envelope.expires_at_unix_ms,
            published_by: "test",
        },
    )
    .await
    .unwrap();
}

async fn setup() -> Option<(TestDb, Client)> {
    let db = TestDb::create("rule_meta").await?;
    let mut client = db.pool.get().await.unwrap();
    platform_store::rules::add_trust_key(
        &mut client,
        "baseline",
        "test-key",
        SigningKey::from_bytes(&TRUSTED).verifying_key().to_bytes(),
    )
    .await
    .unwrap();
    Some((db, client))
}

#[tokio::test]
async fn a_verified_bundle_is_indexed_with_explain_and_check() {
    let Some((db, mut client)) = setup().await else {
        return;
    };
    store(&mut client, 1, TRUSTED).await;
    assert!(
        openvibes_console::index_rule_bundle(&client, "baseline", 1)
            .await
            .unwrap()
    );
    let meta = rule_meta::get(&client, "baseline", 1, "web-server-spawns-shell", 3)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(meta.title, "Web server spawns a shell");
    assert_eq!(meta.message, "A web server started a shell");
    // Capped at 600 characters, on a character boundary.
    assert_eq!(meta.explain, Some("é".repeat(600)));
    assert_eq!(
        meta.check.as_deref(),
        Some("Look at the parent web server's requests.")
    );
    assert_eq!(
        meta.attack,
        [
            ("TA0002".to_owned(), Some("T1059.004".to_owned())),
            ("TA0003".to_owned(), None)
        ]
    );
    // A rule without the text falls back to its title and message.
    let plain = rule_meta::get(&client, "baseline", 1, "plain", 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((plain.explain, plain.check), (None, None));
    assert!(plain.attack.is_empty());
    db.drop().await;
}

#[tokio::test]
async fn an_unverifiable_bundle_is_not_indexed() {
    let Some((db, mut client)) = setup().await else {
        return;
    };
    store(&mut client, 1, [9; 32]).await;
    assert!(
        !openvibes_console::index_rule_bundle(&client, "baseline", 1)
            .await
            .unwrap()
    );
    assert_eq!(
        rule_meta::get(&client, "baseline", 1, "web-server-spawns-shell", 3)
            .await
            .unwrap(),
        None
    );
    db.drop().await;
}

#[tokio::test]
async fn the_backfill_indexes_stored_bundles_once() {
    let Some((db, mut client)) = setup().await else {
        return;
    };
    store(&mut client, 1, TRUSTED).await;
    store(&mut client, 2, [9; 32]).await;
    store(&mut client, 3, TRUSTED).await;
    // Removing the key later does not stop indexing what it signed.
    platform_store::rules::remove_trust_key(&client, "baseline", "test-key")
        .await
        .unwrap();
    let first = openvibes_console::backfill_rule_meta(&client)
        .await
        .unwrap();
    assert_eq!((first.indexed, first.skipped), (2, 1));
    let second = openvibes_console::backfill_rule_meta(&client)
        .await
        .unwrap();
    assert_eq!((second.indexed, second.skipped), (0, 1));
    let versions: Vec<i64> = client
        .query(
            "SELECT DISTINCT rule_set_version FROM console_rule_meta ORDER BY 1",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(versions, [1, 3]);
    db.drop().await;
}
