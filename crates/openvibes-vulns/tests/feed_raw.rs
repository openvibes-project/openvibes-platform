//! `feedfmt::verify` on raw bytes: what the shared vectors cannot say because
//! they are re-serialized from parsed JSON. Each case is signed correctly, so
//! the refusal can only come from the bytes themselves.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_vulns::feedfmt::{self, Refusal, TrustedKey, preimage};

const NOW: i64 = 1_800_000_000;

fn trusted() -> Vec<TrustedKey> {
    vec![TrustedKey {
        feed_id: "site".into(),
        key_id: "k1".into(),
        public_key: SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes(),
    }]
}

fn manifest(sequence: &str) -> String {
    format!(
        r#"{{"sequence":{sequence},"created_at":{},"expires_at":{},"files":[{{"source":"kev","kind":"kev","name":"k.json","sha256":"{}","size":3,"fetched_at":{},"upstream":"https://www.cisa.gov/k.json"}}]}}"#,
        NOW - 60,
        NOW + 3600,
        "a".repeat(64),
        NOW - 120
    )
}

/// An envelope as raw text around a signed `manifest`; `extra` is inserted
/// into the envelope object.
fn envelope(manifest: &str, format: &str, extra: &str) -> Vec<u8> {
    let key = SigningKey::from_bytes(&[3; 32]);
    let signature = URL_SAFE_NO_PAD.encode(key.sign(&preimage("site", "k1", manifest)).to_bytes());
    let manifest = serde_json::to_string(manifest).unwrap();
    format!(
        r#"{{"format":{format},"feed_id":"site","key_id":"k1","signature":"{signature}","manifest":{manifest}{extra}}}"#
    )
    .into_bytes()
}

fn verify(bytes: &[u8]) -> Result<(), Refusal> {
    feedfmt::verify(bytes, &trusted(), &[], NOW).map(|_| ())
}

#[test]
fn a_plain_signed_feed_is_accepted() {
    assert_eq!(verify(&envelope(&manifest("7"), "1", "")), Ok(()));
}

#[test]
fn the_envelope_is_strict_json() {
    let good = manifest("7");
    for (what, bytes) in [
        ("duplicate key", envelope(&good, "1", r#","format":1"#)),
        ("format 1.0", envelope(&good, "1.0", "")),
        ("unknown field", envelope(&good, "1", r#","extra":1"#)),
        ("byte order mark", {
            let mut b = vec![0xEF, 0xBB, 0xBF];
            b.extend(envelope(&good, "1", ""));
            b
        }),
    ] {
        assert_eq!(verify(&bytes), Err(Refusal::BadFormat), "{what}");
    }
}

#[test]
fn the_size_limit_counts_bytes_not_characters() {
    // 600,000 two-byte characters: under 1,048,576 characters, over 1 MiB.
    let big = "é".repeat(600_000);
    let bytes = format!(
        r#"{{"format":1,"feed_id":"site","key_id":"k1","signature":"x","manifest":"{big}"}}"#
    );
    assert!(bytes.chars().count() < 1 << 20 && bytes.len() > 1 << 20);
    assert_eq!(verify(bytes.as_bytes()), Err(Refusal::BadFormat));
}

#[test]
fn the_signed_manifest_is_strict_json_too() {
    let dup = manifest("7").replacen(r#""sequence":7"#, r#""sequence":7,"sequence":8"#, 1);
    let lone = manifest("7").replacen("k.json", r"k\ud800.json", 1);
    for (what, text) in [
        ("duplicate key", dup),
        ("412.0", manifest("412.0")),
        ("4.12e2", manifest("4.12e2")),
        ("lone surrogate", lone),
        ("not an object", "[1,2]".to_owned()),
        ("not JSON", "nope".to_owned()),
    ] {
        assert_eq!(
            verify(&envelope(&text, "1", "")),
            Err(Refusal::BadManifest),
            "{what}"
        );
    }
}

#[test]
fn nothing_is_parsed_before_the_signature() {
    let mut bytes = envelope("not json", "1", "");
    // Corrupt the signature: it must win over the unreadable manifest.
    let at = String::from_utf8_lossy(&bytes)
        .find(r#""signature":""#)
        .unwrap()
        + 14;
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    assert_eq!(verify(&bytes), Err(Refusal::BadSignature));
}
