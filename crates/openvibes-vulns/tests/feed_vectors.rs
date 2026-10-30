//! The shared feed vectors of openvibes-protocol (`spec/feed-v1.md`) against
//! the verifier: signatures, whole-feed cases in order, and per-file checks.

use std::path::Path;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use openvibes_vulns::feedfmt::{self, Applied, FileEntry, Kind, TrustedKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vectors(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{path:?}")))
        .unwrap()
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}

/// Strict base64url, as the rule envelope code reads keys.
fn raw(text: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    (URL_SAFE_NO_PAD.encode(&bytes) == text).then_some(bytes)
}

#[test]
fn signature_vectors_match_verify_strict() {
    let file = vectors("feed-signature.json");
    let cases = file["cases"].as_array().unwrap();
    assert!(cases.len() >= 14);
    for case in cases {
        let pre = feedfmt::preimage(
            text(case, "feed_id"),
            text(case, "key_id"),
            text(case, "manifest"),
        );
        assert_eq!(
            feedfmt::hex(&Sha256::digest(&pre)),
            text(case, "preimage_sha256"),
            "{}",
            case["name"]
        );
        let accepted = (|| {
            let key: [u8; 32] = raw(text(case, "public_key"))?.try_into().ok()?;
            let signature: [u8; 64] = raw(text(case, "signature"))?.try_into().ok()?;
            let key = VerifyingKey::from_bytes(&key).ok()?;
            (!key.is_weak()
                && key
                    .verify_strict(&pre, &Signature::from_bytes(&signature))
                    .is_ok())
            .then_some(())
        })()
        .is_some();
        assert_eq!(
            accepted,
            case["valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

fn trusted(map: &Value) -> Vec<TrustedKey> {
    map.as_object()
        .unwrap()
        .iter()
        .map(|(id, key)| {
            let (feed_id, key_id) = id.split_once('/').unwrap();
            TrustedKey {
                feed_id: feed_id.into(),
                key_id: key_id.into(),
                public_key: raw(key.as_str().unwrap()).unwrap().try_into().unwrap(),
            }
        })
        .collect()
}

fn applied(map: &Value) -> Vec<Applied> {
    map.as_object()
        .unwrap()
        .iter()
        .map(|(id, state)| {
            let (feed_id, key_id) = id.split_once('/').unwrap();
            let digest = text(state, "manifest_digest");
            Applied {
                feed_id: feed_id.into(),
                key_id: key_id.into(),
                sequence: state["sequence"].as_u64().unwrap(),
                manifest_digest: (0..32)
                    .map(|i| u8::from_str_radix(&digest[2 * i..2 * i + 2], 16).unwrap())
                    .collect::<Vec<u8>>()
                    .try_into()
                    .unwrap(),
            }
        })
        .collect()
}

#[test]
fn verification_vectors_give_the_expected_outcome_and_reason() {
    let file = vectors("feed-verification.json");
    let cases = file["cases"].as_array().unwrap();
    assert!(cases.len() >= 30);
    for case in cases {
        // The envelope is given parsed; the verifier reads bytes.
        let bytes = serde_json::to_vec(&case["envelope"]).unwrap();
        let outcome = feedfmt::verify(
            &bytes,
            &trusted(&case["trusted"]),
            &applied(&case["state"]),
            case["now"].as_i64().unwrap(),
        );
        let name = &case["name"];
        match (text(case, "expect"), outcome) {
            ("accepted", Ok(_)) => {}
            ("refused", Err(refusal)) => {
                assert_eq!(refusal.as_str(), text(case, "reason"), "{name}")
            }
            (expect, got) => panic!("{name}: want {expect}, got {:?}", got.map(|_| "accepted")),
        }
    }
}

#[test]
fn an_oversized_envelope_is_refused_before_it_is_parsed() {
    let big = vec![b' '; feedfmt::MAX_ENVELOPE + 1];
    assert_eq!(
        feedfmt::verify(&big, &[], &[], 0).unwrap_err().as_str(),
        "bad_format"
    );
}

#[test]
fn file_vectors_give_the_expected_reason() {
    let file = vectors("feed-files.json");
    for case in file["cases"].as_array().unwrap() {
        let entry = &case["entry"];
        let entry = FileEntry {
            source: text(entry, "source").into(),
            kind: Kind::Updateinfo,
            name: text(entry, "name").into(),
            sha256: text(entry, "sha256").into(),
            size: entry["size"].as_u64().unwrap(),
            fetched_at: entry["fetched_at"].as_i64().unwrap(),
            upstream: text(entry, "upstream").into(),
            releases: None,
        };
        let hex = text(case, "blob_hex");
        let blob: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let got = feedfmt::check_file(
            &entry,
            blob.len() as u64,
            &feedfmt::hex(&Sha256::digest(&blob)),
            case["applied_fetched_at"].as_i64(),
            case["reader_limit"].as_u64().unwrap(),
        );
        let want = text(case, "expect");
        match got {
            Ok(()) => assert_eq!(want, "ok", "{}", case["name"]),
            Err(refusal) => assert_eq!(refusal.as_str(), want, "{}", case["name"]),
        }
    }
}

#[test]
fn a_fingerprint_is_eight_groups_of_four() {
    let fingerprint = feedfmt::fingerprint(&[7; 32]);
    let groups: Vec<&str> = fingerprint.split(' ').collect();
    assert_eq!(groups.len(), 8);
    assert!(
        groups
            .iter()
            .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_hexdigit()))
    );
}

#[test]
fn public_keys_must_be_canonical_and_not_weak() {
    let good = vectors("feed-signature.json")["keys"]["1"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(feedfmt::parse_public_key(&good).is_some());
    assert!(feedfmt::parse_public_key(&format!("{good}=")).is_none());
    assert!(feedfmt::parse_public_key(&URL_SAFE_NO_PAD.encode([1u8; 31])).is_none());
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(feedfmt::parse_public_key(&URL_SAFE_NO_PAD.encode(identity)).is_none());
}
