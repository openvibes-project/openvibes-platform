//! Writes a signed rule bundle for `scripts/integration-agent.sh` and prints
//! its base64url public key. `OUT_FILE [VERSION [PAD_RULES]]`: version 2 and
//! above add the rule `integration.v2`, so a finding shows the agent runs it;
//! PAD_RULES adds never-matching rules of about 2 KB each (load tests). Test-only: the seed is a published constant
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
    let parsed = match args.as_slice() {
        [out] => Some((out, 1, 0)),
        [out, version] => version.parse().ok().map(|v| (out, v, 0)),
        [out, version, pad] => version
            .parse()
            .ok()
            .zip(pad.parse().ok())
            .map(|(v, p)| (out, v, p)),
        _ => None,
    };
    let Some((out, version, pad)) =
        parsed.filter(|&(_, version, pad): &(_, u64, usize)| version >= 1 && pad <= 500)
    else {
        eprintln!("usage: integration_bundle OUT_FILE [VERSION [PAD_RULES]]");
        return ExitCode::from(2);
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        });
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut rules = vec![
        rule("integration.processes", "facts['process.count'] >= 1"),
        rule(
            "integration.processes.nonnegative",
            "facts['process.count'] >= 0",
        ),
    ];
    if version >= 2 {
        rules.push(rule("integration.v2", "facts['process.count'] >= 1"));
    }
    for n in 0..pad {
        let mut padding = rule(
            &format!("integration.pad.{n:03}"),
            "facts['process.count'] < 0",
        );
        padding.finding_message = "x".repeat(2_000);
        rules.push(padding);
    }
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules,
    })
    .expect("rule set serializes");
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: Identifier::new("integration").expect("valid id"),
        rule_set_version: version,
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
