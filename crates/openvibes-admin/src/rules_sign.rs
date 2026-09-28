//! `openvibes-admin rules keygen|sign`: offline rule signing on the
//! signer's machine. No config, database or audit row; the platform never
//! holds a rule-signing key.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{
    Identifier, PayloadEncoding, ResourceLimits, RuleSet, SchemaVersion, SignedRuleEnvelope,
    Validate,
};
use openvibes_rules::{LoadContext, RuleLoader, TrustedRuleKey, signing_preimage};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const DAY_MS: i64 = 86_400_000;

/// `rules sign` arguments.
pub struct SignArgs<'a> {
    pub key: &'a Path,
    pub rules: &'a Path,
    pub rule_set: &'a str,
    pub version: u64,
    pub issuer: &'a str,
    pub days: u32,
    pub out: &'a Path,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn identifier(label: &str, value: &str) -> Result<Identifier, String> {
    Identifier::new(value).map_err(|e| format!("{label}: {e}"))
}

/// Writes `bytes` to a file that must not exist yet, and flushes the file
/// and its directory entry to disk: a key's trust line is printed only once
/// the key is durable.
fn create_new(path: &Path, mode: u32, bytes: &[u8]) -> Result<(), String> {
    let parent = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| File::open(parent)?.sync_all())
        .map_err(|e| format!("cannot create {}: {e}", path.display()))
}

/// Makes a new Ed25519 key in `path` (0600) and returns the trust line
/// `RULE_SET ISSUER_KEY_ID PUBLIC_KEY`.
pub fn keygen(path: &Path, rule_set: &str, issuer: &str) -> Result<String, String> {
    identifier("rule set", rule_set)?;
    identifier("issuer key id", issuer)?;
    let mut seed = [0u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| "no randomness available".to_owned())?;
    let written = create_new(path, 0o600, &seed);
    let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    seed.zeroize();
    written?;
    Ok(format!(
        "{rule_set} {issuer} {}\n",
        URL_SAFE_NO_PAD.encode(public)
    ))
}

/// Reads a private key that only its owner can access.
fn read_key(path: &Path) -> Result<SigningKey, String> {
    let shown = path.display();
    let meta = fs::metadata(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{shown} is not a regular file"));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{shown} is accessible to group or others: chmod 600 {shown} \
             (a FAT/exFAT stick cannot hold 0600: sign from a copy in \
             $XDG_RUNTIME_DIR, then delete it)"
        ));
    }
    let mut bytes = fs::read(path).map_err(|e| format!("cannot read {shown}: {e}"))?;
    let seed: Result<[u8; 32], _> = bytes.as_slice().try_into();
    bytes.zeroize();
    let mut seed = seed.map_err(|_| format!("{shown} must hold exactly 32 bytes"))?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

/// Signs the exact bytes of a rule set file into a new envelope file,
/// after proving the agent's loader accepts it.
pub fn sign(args: &SignArgs<'_>, now_ms: i64) -> Result<String, String> {
    let id = identifier("rule set", args.rule_set)?;
    let issuer = identifier("issuer key id", args.issuer)?;
    let key = read_key(args.key)?;
    let payload = fs::read_to_string(args.rules)
        .map_err(|e| format!("cannot read {}: {e}", args.rules.display()))?;
    let rules: RuleSet =
        serde_json::from_str(&payload).map_err(|e| format!("invalid rule set: {e}"))?;
    rules
        .validate(ResourceLimits::V1)
        .map_err(|e| format!("invalid rule set: {e}"))?;
    let expires = now_ms + i64::from(args.days) * DAY_MS;
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id.clone(),
        rule_set_version: args.version,
        issuer_key_id: issuer.clone(),
        created_at_unix_ms: now_ms,
        expires_at_unix_ms: expires,
        payload_encoding: PayloadEncoding::Json,
        payload_sha256_hex: hex(&Sha256::digest(payload.as_bytes())),
        payload,
        signature_base64url: String::new(),
    };
    let preimage = signing_preimage(&envelope, ResourceLimits::V1).map_err(|e| e.to_string())?;
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes());
    let bytes = serde_json::to_vec_pretty(&envelope).map_err(|e| e.to_string())?;
    // Prove the agent accepts it before writing it.
    let trusted = TrustedRuleKey::new(id.clone(), issuer, key.verifying_key().to_bytes())
        .map_err(|e| e.to_string())?;
    RuleLoader::new(vec![trusted], ResourceLimits::V1)
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
        .map_err(|e| format!("the signed envelope does not load: {e}"))?;
    create_new(args.out, 0o644, &bytes)?;
    let expires_at = DateTime::from_timestamp_millis(expires)
        .ok_or("expiry out of range")?
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    Ok(format!(
        "signed {} v{}, expires {expires_at}, sha256 {}\n",
        args.rule_set,
        args.version,
        hex(&Sha256::digest(&bytes))
    ))
}
