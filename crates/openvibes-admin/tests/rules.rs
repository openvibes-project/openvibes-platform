//! `openvibes-admin rules`: trust keys and verified publishing.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use std::{
    path::PathBuf,
    process::Output,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Fixture, scratch_dir, stdout};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{
    Confidence, Identifier, PayloadEncoding, ResourceLimits, Rule, RuleSet, SchemaVersion,
    Severity, SignedRuleEnvelope,
};
use sha2::{Digest, Sha256};

const DAY_MS: i64 = 86_400_000;

fn now_ms() -> i64 {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    i64::try_from(elapsed.as_millis()).unwrap()
}

fn public(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

/// A `baseline` envelope signed as `org.rules` by the key from `seed`.
fn sign(version: u64, seed: u8, expires_in_ms: i64) -> Vec<u8> {
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: vec![Rule {
            id: Identifier::new("baseline.rule").unwrap(),
            version: 1,
            title: "Rule".into(),
            severity: Severity::Info,
            confidence: Confidence::new(100).unwrap(),
            expression: "facts['process.count'] >= 1".into(),
            finding_message: format!("version {version}"),
        }],
    })
    .unwrap();
    let now = now_ms();
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: Identifier::new("baseline").unwrap(),
        rule_set_version: version,
        issuer_key_id: Identifier::new("org.rules").unwrap(),
        created_at_unix_ms: now - DAY_MS,
        expires_at_unix_ms: now + expires_in_ms,
        payload_encoding: PayloadEncoding::Json,
        payload_sha256_hex: Sha256::digest(payload.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        payload,
        signature_base64url: String::new(),
    };
    let preimage = openvibes_rules::signing_preimage(&envelope, ResourceLimits::V1).unwrap();
    let key = SigningKey::from_bytes(&[seed; 32]);
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes());
    serde_json::to_vec(&envelope).unwrap()
}

fn write(dir: &std::path::Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn failed(output: &Output, message: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unexpected success: {stderr}");
    assert!(stderr.contains(message), "want {message:?}, got {stderr}");
}

async fn ready(test: &str) -> (Fixture, PathBuf) {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    (fixture, scratch_dir(test))
}

fn trust(fixture: &Fixture, seed: u8) {
    stdout(&fixture.run(&[
        "rules",
        "trust",
        "add",
        "baseline",
        "org.rules",
        &public(seed),
    ]));
}

fn publish(fixture: &Fixture, file: &std::path::Path) -> Output {
    fixture.run(&["rules", "publish", file.to_str().unwrap()])
}

async fn stored(fixture: &Fixture) -> i64 {
    fixture.count("SELECT count(*) FROM rule_bundles").await
}

#[tokio::test]
async fn publish_stores_the_exact_bytes() {
    let (fixture, dir) = ready("exact").await;
    trust(&fixture, 7);
    let bytes = sign(1, 7, 30 * DAY_MS);
    let out = stdout(&publish(&fixture, &write(&dir, "v1.json", &bytes)));
    assert_eq!(out, "published baseline v1\n");
    let pool = platform_store::connect(&fixture.url).await.unwrap();
    let client = pool.get().await.unwrap();
    let row = client
        .query_one("SELECT envelope FROM rule_bundles", &[])
        .await
        .unwrap();
    assert_eq!(row.get::<_, Vec<u8>>(0), bytes);
    let digest: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let audit = fixture.audit_targets().await;
    assert!(audit.contains(&(
        "rules publish".into(),
        Some(format!("baseline v1 sha256:{digest}")),
        "ok".into()
    )));
    fixture.drop().await;
}

#[tokio::test]
async fn publish_refuses_an_untrusted_issuer() {
    let (fixture, dir) = ready("untrusted").await;
    failed(
        &publish(&fixture, &write(&dir, "v1.json", &sign(1, 7, DAY_MS * 30))),
        "untrusted issuer",
    );
    trust(&fixture, 8);
    failed(
        &publish(&fixture, &write(&dir, "v1.json", &sign(1, 7, DAY_MS * 30))),
        "invalid signature",
    );
    assert_eq!(stored(&fixture).await, 0);
    fixture.drop().await;
}

#[tokio::test]
async fn publish_refuses_a_bad_signature() {
    let (fixture, dir) = ready("badsig").await;
    trust(&fixture, 7);
    let mut envelope: SignedRuleEnvelope =
        serde_json::from_slice(&sign(1, 7, 30 * DAY_MS)).unwrap();
    envelope.expires_at_unix_ms += 1;
    let file = write(&dir, "v1.json", &serde_json::to_vec(&envelope).unwrap());
    failed(&publish(&fixture, &file), "invalid signature");
    assert_eq!(stored(&fixture).await, 0);
    fixture.drop().await;
}

#[tokio::test]
async fn publish_refuses_an_expired_envelope() {
    let (fixture, dir) = ready("expired").await;
    trust(&fixture, 7);
    failed(
        &publish(&fixture, &write(&dir, "v1.json", &sign(1, 7, -1))),
        "expired",
    );
    assert_eq!(stored(&fixture).await, 0);
    fixture.drop().await;
}

#[tokio::test]
async fn publish_warns_when_expiry_is_near() {
    let (fixture, dir) = ready("near").await;
    trust(&fixture, 7);
    let output = publish(&fixture, &write(&dir, "v1.json", &sign(1, 7, 2 * DAY_MS)));
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("expires in less than 7 days"));
    fixture.drop().await;
}

#[tokio::test]
async fn publish_refuses_old_or_conflicting_versions() {
    let (fixture, dir) = ready("versions").await;
    trust(&fixture, 7);
    let v2 = write(&dir, "v2.json", &sign(2, 7, 30 * DAY_MS));
    stdout(&publish(&fixture, &v2));
    failed(
        &publish(&fixture, &write(&dir, "v1.json", &sign(1, 7, 30 * DAY_MS))),
        "version 1 is not above current version 2",
    );
    // Re-signed later: same version, different bytes.
    let other = write(&dir, "v2b.json", &sign(2, 7, 31 * DAY_MS));
    failed(
        &publish(&fixture, &other),
        "version 2 already published with different content",
    );
    assert_eq!(
        stdout(&publish(&fixture, &v2)),
        "unchanged: baseline v2 already published\n"
    );
    assert_eq!(stored(&fixture).await, 1);
    fixture.drop().await;
}

#[tokio::test]
async fn publish_refuses_a_removed_key() {
    let (fixture, dir) = ready("removed").await;
    trust(&fixture, 7);
    stdout(&publish(
        &fixture,
        &write(&dir, "v1.json", &sign(1, 7, 30 * DAY_MS)),
    ));
    stdout(&fixture.run(&["rules", "trust", "remove", "baseline", "org.rules"]));
    let listed = stdout(&fixture.run(&["rules", "list"]));
    assert!(listed.contains(" signer-removed"), "{listed}");
    failed(
        &publish(&fixture, &write(&dir, "v2.json", &sign(2, 7, 30 * DAY_MS))),
        "untrusted issuer",
    );
    assert_eq!(stored(&fixture).await, 1);
    fixture.drop().await;
}

#[tokio::test]
async fn publish_refuses_an_oversized_file() {
    let (fixture, dir) = ready("oversized").await;
    trust(&fixture, 7);
    let file = write(&dir, "big.json", &vec![b' '; 1_048_577]);
    failed(&publish(&fixture, &file), "larger than 1048576 bytes");
    failed(
        &publish(&fixture, &write(&dir, "junk.json", b"{}")),
        "not a signed rule envelope",
    );
    fixture.drop().await;
}

#[tokio::test]
async fn trust_add_rejects_bad_keys() {
    let (fixture, _dir) = ready("badkeys").await;
    let short = URL_SAFE_NO_PAD.encode([1u8; 31]);
    let weak = URL_SAFE_NO_PAD.encode([0u8; 32]);
    for key in ["not base64!", short.as_str(), weak.as_str()] {
        failed(
            &fixture.run(&["rules", "trust", "add", "baseline", "org.rules", key]),
            "invalid public key",
        );
    }
    failed(
        &fixture.run(&["rules", "trust", "add", "a/b", "org.rules", &public(7)]),
        "invalid identifier",
    );
    trust(&fixture, 7);
    let again =
        stdout(&fixture.run(&["rules", "trust", "add", "baseline", "org.rules", &public(7)]));
    assert_eq!(again, "already trusted\n");
    failed(
        &fixture.run(&["rules", "trust", "add", "baseline", "org.rules", &public(8)]),
        "issuer key id already used",
    );
    fixture.drop().await;
}

#[tokio::test]
async fn list_show_retire_round_trip() {
    let (fixture, dir) = ready("roundtrip").await;
    trust(&fixture, 7);
    stdout(&publish(
        &fixture,
        &write(&dir, "v1.json", &sign(1, 7, 30 * DAY_MS)),
    ));
    stdout(&publish(
        &fixture,
        &write(&dir, "v2.json", &sign(2, 7, 30 * DAY_MS)),
    ));
    let listed = stdout(&fixture.run(&["rules", "list"]));
    assert!(
        listed.starts_with("baseline v2 keys 1 expires "),
        "{listed}"
    );
    let shown = stdout(&fixture.run(&["rules", "show", "baseline"]));
    let versions: Vec<_> = shown
        .lines()
        .map(|l| l.split(' ').next().unwrap())
        .collect();
    assert_eq!(versions, ["v2", "v1"]);
    assert!(shown.contains("issuer org.rules"));
    let keys = stdout(&fixture.run(&["rules", "trust", "list"]));
    assert!(
        keys.starts_with(&format!("baseline org.rules {} added ", public(7))),
        "{keys}"
    );
    assert_eq!(
        stdout(&fixture.run(&["rules", "retire", "baseline"])),
        "retired baseline\n"
    );
    assert!(
        stdout(&fixture.run(&["rules", "list"]))
            .trim_end()
            .ends_with("retired")
    );
    failed(
        &fixture.run(&["rules", "retire", "baseline"]),
        "unknown or already retired rule set",
    );
    failed(
        &fixture.run(&["rules", "show", "nobody"]),
        "unknown rule set",
    );
    failed(
        &publish(&fixture, &write(&dir, "v3.json", &sign(3, 7, 30 * DAY_MS))),
        "rule set is retired",
    );
    fixture.drop().await;
}

#[tokio::test]
async fn every_rules_command_is_audited() {
    let (fixture, dir) = ready("audited").await;
    let _ = publish(&fixture, &write(&dir, "junk.json", b"{}"));
    trust(&fixture, 7);
    let _ = fixture.run(&["rules", "list"]);
    let actions = fixture.audit_targets().await;
    assert!(
        actions.contains(&("rules publish".into(), None, "error".into())),
        "{actions:?}"
    );
    assert!(actions.contains(&(
        "rules trust add".into(),
        Some("baseline/org.rules".into()),
        "ok".into()
    )));
    assert!(actions.contains(&("rules list".into(), None, "ok".into())));
    fixture.drop().await;
}

#[tokio::test]
async fn publish_refuses_every_invalid_protocol_fixture() {
    let (fixture, _dir) = ready("fixtures").await;
    // The fixtures' issuer is trusted, so each is refused for its own defect.
    stdout(&fixture.run(&["rules", "trust", "add", "baseline", "org.rules", &public(7)]));
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/fixtures/v1/signed-rule-envelope");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("protocol fixtures; git submodule update --init") {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if !name.starts_with("invalid") {
            continue;
        }
        let output = publish(&fixture, &path);
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(!output.status.success(), "{name} was published");
        assert!(!stderr.contains("untrusted issuer"), "{name}: {stderr}");
        checked += 1;
    }
    assert!(checked >= 3, "only {checked} invalid fixtures");
    assert_eq!(stored(&fixture).await, 0);
    fixture.drop().await;
}
