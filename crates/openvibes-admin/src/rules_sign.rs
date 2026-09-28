//! `openvibes-admin rules keygen|sign`: offline rule signing on the
//! signer's machine. No config, database or audit row; the platform never
//! holds a rule-signing key.

use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::Path};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use openvibes_core::Identifier;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;

fn identifier(label: &str, value: &str) -> Result<Identifier, String> {
    Identifier::new(value).map_err(|e| format!("{label}: {e}"))
}

/// Writes `bytes` to a file that must not exist yet.
fn create_new(path: &Path, mode: u32, bytes: &[u8]) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
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
