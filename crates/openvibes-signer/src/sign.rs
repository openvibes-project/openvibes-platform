//! Checking a site rule set and signing it with the site key.

use std::{collections::BTreeSet, fs, os::unix::fs::PermissionsExt, path::Path};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{
    Identifier, PayloadEncoding, ResourceLimits, RuleKind, RuleSet, SchemaVersion,
    SignedRuleEnvelope, Validate,
};
use openvibes_rules::{
    LoadContext, RuleLoader, TrustedRuleKey, compile_event_rules, signing_preimage,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::request::{Refusal, SITE, SITE_ALARMS};

const DAY_MS: i64 = 86_400_000;
/// Contract P14 "Restricted rule sets": `programs` per alarm rule (distinct),
/// and distinct across the set. The agent refuses more; so does the signer,
/// so a refused rule never ships.
const RULE_PROGRAMS: usize = 8;
const SET_PROGRAMS: usize = 32;

/// Creates the site key at `path` (0600) unless it exists, and returns
/// its public half, base64url, for agents' trust lines.
///
/// # Errors
/// No randomness, or the key can't be written or read back.
pub fn create_key(path: &Path) -> Result<String, String> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    if !path.exists() {
        let mut seed = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed)
            .map_err(|_| "no randomness available".to_owned())?;
        let written = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut file| {
                file.write_all(&seed)?;
                file.sync_all()
            });
        seed.zeroize();
        written.map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    }
    Ok(URL_SAFE_NO_PAD.encode(read_key(path)?.verifying_key().to_bytes()))
}

/// Reads the site key: a regular file of exactly 32 bytes that only its
/// owner can read.
///
/// # Errors
/// A missing, unreadable, shared or malformed key file.
pub fn read_key(path: &Path) -> Result<SigningKey, String> {
    let shown = path.display();
    let meta = fs::metadata(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err(format!("{shown} must be a regular file with mode 0600"));
    }
    let mut bytes = fs::read(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    let seed: Result<[u8; 32], _> = bytes.as_slice().try_into();
    bytes.zeroize();
    let mut seed = seed.map_err(|_| format!("{shown} must hold exactly 32 bytes"))?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

/// Checks `payload` as the rules of `rule_set`: valid, at most `max_rules`,
/// only snapshot rules in `site` and only alarm rules in `site-alarms`,
/// and the alarm rules within the restricted-set `programs` caps.
///
/// # Errors
/// [`Refusal::Invalid`] or [`Refusal::Limits`].
pub fn check_rules(rule_set: &str, payload: &str, max_rules: usize) -> Result<(), Refusal> {
    let rules: RuleSet = serde_json::from_str(payload).map_err(|_| Refusal::Invalid)?;
    rules
        .validate(ResourceLimits::V1)
        .map_err(|_| Refusal::Invalid)?;
    if rules.rules.is_empty() {
        return Err(Refusal::Invalid);
    }
    if rules.rules.len() > max_rules {
        return Err(Refusal::Limits);
    }
    let alarms = rule_set == SITE_ALARMS;
    if rules
        .rules
        .iter()
        .any(|rule| (rule.kind == RuleKind::ProcessEvent) != alarms)
    {
        return Err(Refusal::Invalid);
    }
    if alarms {
        let mut all = BTreeSet::new();
        for rule in &rules.rules {
            let named: BTreeSet<&String> = rule.programs.iter().flatten().collect();
            if !(1..=RULE_PROGRAMS).contains(&named.len()) {
                return Err(Refusal::Limits);
            }
            all.extend(named);
        }
        if all.len() > SET_PROGRAMS {
            return Err(Refusal::Limits);
        }
    }
    Ok(())
}

/// A signed envelope.
pub struct Signed {
    /// The envelope JSON.
    pub envelope: String,
    /// When it expires.
    pub expires_at_unix_ms: i64,
    /// SHA-256 of the envelope, for the audit line.
    pub sha256: String,
}

/// Signs `payload` (already checked) as `rule_set` version `version`, and
/// proves the agent's loader accepts it, and for alarm rules that every
/// rule compiles, before returning it.
///
/// # Errors
/// [`Refusal::Invalid`] when the loader or the compiler refuses it.
pub fn sign(
    key: &SigningKey,
    issuer: &str,
    rule_set: &str,
    version: u64,
    payload: &str,
    now_ms: i64,
    days: u32,
) -> Result<Signed, Refusal> {
    debug_assert!(rule_set == SITE || rule_set == SITE_ALARMS);
    let id = Identifier::new(rule_set).map_err(|_| Refusal::Invalid)?;
    let issuer = Identifier::new(issuer).map_err(|_| Refusal::Invalid)?;
    let expires = now_ms + i64::from(days) * DAY_MS;
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id.clone(),
        rule_set_version: version,
        issuer_key_id: issuer.clone(),
        created_at_unix_ms: now_ms,
        expires_at_unix_ms: expires,
        payload_encoding: PayloadEncoding::Json,
        payload_sha256_hex: hex(&Sha256::digest(payload.as_bytes())),
        payload: payload.to_owned(),
        signature_base64url: String::new(),
    };
    let preimage = signing_preimage(&envelope, ResourceLimits::V1).map_err(|_| Refusal::Invalid)?;
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes());
    let bytes = serde_json::to_vec_pretty(&envelope).map_err(|_| Refusal::Invalid)?;
    let trusted = TrustedRuleKey::new(id.clone(), issuer, key.verifying_key().to_bytes())
        .map_err(|_| Refusal::Invalid)?;
    let verified = RuleLoader::new(vec![trusted], ResourceLimits::V1)
        .and_then(|loader| {
            loader.load_json(
                &bytes,
                LoadContext {
                    expected_rule_set_id: &id,
                    now_unix_ms: now_ms,
                    last_accepted: None,
                },
            )
        })
        .map_err(|_| Refusal::Invalid)?;
    if !compile_event_rules(&verified, ResourceLimits::V1)
        .refused
        .is_empty()
    {
        return Err(Refusal::Invalid);
    }
    Ok(Signed {
        sha256: hex(&Sha256::digest(&bytes)),
        envelope: String::from_utf8(bytes).map_err(|_| Refusal::Invalid)?,
        expires_at_unix_ms: expires,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
