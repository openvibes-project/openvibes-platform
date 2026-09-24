//! Writes a signed rule bundle for `scripts/integration-agent.sh` and prints
//! its base64url public key. `OUT_FILE [VERSION [PAD_RULES [SEED]]]`:
//! version 2 and above add the rule `integration.v2`, and 3 and above
//! `integration.v3`, so a finding shows which version the agent runs;
//! PAD_RULES adds never-matching rules of about 2 KB each (load tests). SEED
//! (default 7, issuer `integration.test`) picks another signing key, issuer
//! `integration.seedN`. Test-only: the seeds are published constants (the
//! agent's tests use 7) and sign nothing else.

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
    let arg = |index: usize, default: u64| {
        args.get(index)
            .map_or(Some(default), |value| value.parse::<u64>().ok())
    };
    let parsed = match (args.first(), arg(1, 1), arg(2, 0), arg(3, 7)) {
        (Some(out), Some(version), Some(pad), Some(seed))
            if args.len() <= 4 && version >= 1 && pad <= 500 =>
        {
            u8::try_from(seed)
                .ok()
                .map(|seed| (out, version, pad as usize, seed))
        }
        _ => None,
    };
    let Some((out, version, pad, seed)) = parsed else {
        eprintln!("usage: integration_bundle OUT_FILE [VERSION [PAD_RULES [SEED]]]");
        return ExitCode::from(2);
    };
    let issuer = if seed == 7 {
        "integration.test".to_owned()
    } else {
        format!("integration.seed{seed}")
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        });
    let key = SigningKey::from_bytes(&[seed; 32]);
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
    if version >= 3 {
        rules.push(rule("integration.v3", "facts['process.count'] >= 1"));
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
        issuer_key_id: Identifier::new(&issuer).expect("valid id"),
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
