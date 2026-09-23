//! Writes a signed rule bundle for `scripts/integration-agent.sh` and prints
//! its base64url public key. Test-only: the seed is a published constant
//! (the agent's tests use the same one) and signs nothing else.

use std::{
    path::PathBuf,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{
    Confidence, Identifier, PayloadEncoding, ResourceLimits, Rule, RuleSet, SchemaVersion,
    Severity, SignedRuleEnvelope,
};
use openvibes_rules::signing_preimage;
use sha2::{Digest, Sha256};

const HOUR_MS: i64 = 3_600_000;

fn rule(id: &str, expression: &str) -> Rule {
    Rule {
        id: Identifier::new(id).expect("valid id"),
        version: 1,
        title: "Integration rule".into(),
        severity: Severity::Info,
        confidence: Confidence::new(100).expect("valid confidence"),
        expression: expression.into(),
        finding_message: "Integration test finding".into(),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [out] = args.as_slice() else {
        eprintln!("usage: integration_bundle OUT_FILE");
        return ExitCode::from(2);
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        });
    let key = SigningKey::from_bytes(&[7; 32]);
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: vec![
            rule("integration.processes", "facts['process.count'] >= 1"),
            rule(
                "integration.processes.nonnegative",
                "facts['process.count'] >= 0",
            ),
        ],
    })
    .expect("rule set serializes");
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: Identifier::new("integration").expect("valid id"),
        rule_set_version: 1,
        issuer_key_id: Identifier::new("integration.test").expect("valid id"),
        created_at_unix_ms: now - HOUR_MS,
        expires_at_unix_ms: now + 7 * 24 * HOUR_MS,
        payload_encoding: PayloadEncoding::Json,
        payload_sha256_hex: Sha256::digest(payload.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        payload,
        signature_base64url: String::new(),
    };
    let preimage = signing_preimage(&envelope, ResourceLimits::V1).expect("valid envelope");
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes());
    let bytes = serde_json::to_vec(&envelope).expect("envelope serializes");
    if std::fs::write(PathBuf::from(out), bytes).is_err() {
        eprintln!("integration_bundle: cannot write the bundle");
        return ExitCode::FAILURE;
    }
    println!("{}", URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()));
    ExitCode::SUCCESS
}
