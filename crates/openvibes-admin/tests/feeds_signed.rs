//! `feeds trust` and `feeds import-bundle`: a signed feed is verified before
//! anything is read, replays and changed files are refused, and the audit log
//! names the feed and sequence.
// The test starts the CLI binary it verifies; this is not shipped code.
#![allow(clippy::disallowed_types)]

mod common;

use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Fixture, scratch_dir, stdout};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_vulns::feedfmt::{hex, preimage};
use serde_json::json;
use sha2::{Digest, Sha256};

fn kev() -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../openvibes-vulns/tests/fixtures/kev.json"),
    )
    .unwrap()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// An unpacked mirror tree signed by `seed`'s key, holding `kev`.
fn tree(dir: &Path, seed: u8, key_id: &str, sequence: u64, kev: &[u8]) {
    let sha = hex(&Sha256::digest(kev));
    let manifest = json!({
        "sequence": sequence,
        "created_at": now() - 60,
        "expires_at": now() + 86_400,
        "files": [{
            "source": "cisa", "kind": "kev", "name": "known_exploited_vulnerabilities.json",
            "sha256": sha, "size": kev.len(), "fetched_at": now() - 120,
            "upstream": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        }],
    })
    .to_string();
    let key = SigningKey::from_bytes(&[seed; 32]);
    let signature = key.sign(&preimage("site", key_id, &manifest));
    let envelope = json!({
        "format": 1, "feed_id": "site", "key_id": key_id,
        "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        "manifest": manifest,
    });
    std::fs::create_dir_all(dir.join("blobs")).unwrap();
    std::fs::write(dir.join("feed.json"), envelope.to_string()).unwrap();
    std::fs::write(dir.join("blobs").join(&sha), kev).unwrap();
}

fn public(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

fn failure(fixture: &Fixture, args: &[&str]) -> String {
    let output = fixture.run(args);
    assert!(!output.status.success(), "unexpected success: {args:?}");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[tokio::test]
async fn a_signed_feed_is_applied_only_from_a_trusted_key_and_never_replayed() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let dir = scratch_dir("feeds-signed");
    let mirror = dir.join("mirror");
    tree(&mirror, 1, "k1", 5, &kev());
    let path = mirror.to_string_lossy().into_owned();

    // No trusted key yet: nothing is read.
    assert!(failure(&fixture, &["feeds", "import-bundle", &path]).contains("unknown_key"));

    let added = stdout(&fixture.run(&["feeds", "trust", "add", "site", "k1", &public(1)]));
    assert!(
        added.starts_with("trusted site/k1\nfingerprint "),
        "{added}"
    );
    assert!(
        stdout(&fixture.run(&["feeds", "trust", "list"])).starts_with("site/k1 "),
        "listed"
    );
    // A weak key and a malformed one are refused.
    let zero = URL_SAFE_NO_PAD.encode([0u8; 32]);
    for bad in [zero.as_str(), "short"] {
        assert!(
            failure(&fixture, &["feeds", "trust", "add", "site", "k2", bad])
                .contains("invalid public key")
        );
    }

    let out = stdout(&fixture.run(&["feeds", "import-bundle", &path]));
    assert!(out.contains("signed by k1"), "{out}");
    assert!(out.contains("cisa kev applied"), "{out}");
    let applied = stdout(&fixture.run(&["feeds", "applied"]));
    assert!(
        applied.starts_with("site/k1 sequence 5 from mirror"),
        "{applied}"
    );

    // The same feed again changes nothing.
    let again = stdout(&fixture.run(&["feeds", "import-bundle", &path]));
    assert!(again.contains("cisa kev unchanged"), "{again}");

    // An older one is a replay, a forged one fails its signature.
    let older = dir.join("older");
    tree(&older, 1, "k1", 4, &kev());
    assert!(
        failure(
            &fixture,
            &["feeds", "import-bundle", &older.to_string_lossy()]
        )
        .contains("sequence_replay")
    );
    let forged = dir.join("forged");
    tree(&forged, 2, "k1", 9, &kev());
    assert!(
        failure(
            &fixture,
            &["feeds", "import-bundle", &forged.to_string_lossy()]
        )
        .contains("bad_signature")
    );

    // A blob changed after signing is refused, named, and exits non-zero.
    let changed = dir.join("changed");
    tree(&changed, 1, "k1", 6, &kev());
    let blob = std::fs::read_dir(changed.join("blobs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    std::fs::write(blob.path(), b"tampered").unwrap();
    let said = failure(
        &fixture,
        &["feeds", "import-bundle", &changed.to_string_lossy()],
    );
    assert!(said.contains("cisa kev REFUSED"), "{said}");

    // Removing the key stops the feed.
    stdout(&fixture.run(&["feeds", "trust", "remove", "site", "k1"]));
    assert!(failure(&fixture, &["feeds", "import-bundle", &path]).contains("unknown_key"));

    let audit = fixture.audit().await;
    assert!(
        audit
            .iter()
            .any(|(_, action, result)| action == "feeds import-bundle" && result == "ok"),
        "{audit:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
    fixture.drop().await;
}
