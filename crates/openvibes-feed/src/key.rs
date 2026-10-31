//! The feed signing key: one Ed25519 seed with the feed and key ids it signs
//! as, in a file only its owner can read.

use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use openvibes_vulns::feedfmt;
use ring::rand::{SecureRandom, SystemRandom};

const MAGIC: &str = "openvibes-feed-key-v1";

/// A loaded signing key.
pub struct FeedKey {
    /// The feed this key signs for.
    pub feed_id: String,
    /// The key's id within the feed.
    pub key_id: String,
    /// The private key.
    pub signing: SigningKey,
}

impl std::fmt::Debug for FeedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FeedKey({}/{})", self.feed_id, self.key_id)
    }
}

impl FeedKey {
    /// The public key, canonical base64url (what `feeds trust add` takes).
    #[must_use]
    pub fn public(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing.verifying_key().to_bytes())
    }

    /// The public key's fingerprint, to compare on both sides.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        feedfmt::fingerprint(&self.signing.verifying_key().to_bytes())
    }
}

fn check_ids(feed_id: &str, key_id: &str) -> Result<(), String> {
    if feedfmt::identifier(feed_id) && feedfmt::identifier(key_id) {
        Ok(())
    } else {
        Err("feed and key ids are 1 to 128 of letters, digits, . _ : -".into())
    }
}

/// Makes a new key at `path` (mode 0600, never overwritten).
///
/// # Errors
/// An id is invalid, the file exists, or it cannot be written.
pub fn generate(path: &Path, feed_id: &str, key_id: &str) -> Result<FeedKey, String> {
    check_ids(feed_id, key_id)?;
    let mut seed = [0u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| "no random numbers available".to_owned())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    writeln!(
        file,
        "{MAGIC} {feed_id} {key_id} {}",
        URL_SAFE_NO_PAD.encode(seed)
    )
    .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(FeedKey {
        feed_id: feed_id.to_owned(),
        key_id: key_id.to_owned(),
        signing: SigningKey::from_bytes(&seed),
    })
}

/// Reads a key file made by [`generate`]; group or other access is refused.
///
/// # Errors
/// The file is unreadable, too open, or not a key file.
pub fn load(path: &Path) -> Result<FeedKey, String> {
    let meta =
        std::fs::metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{} must not be readable by group or others (chmod 600)",
            path.display()
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let parts: Vec<&str> = text.split_whitespace().collect();
    let [magic, feed_id, key_id, seed] = parts[..] else {
        return Err("not a feed key file".into());
    };
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(seed)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("not a feed key file")?;
    if magic != MAGIC {
        return Err("not a feed key file".into());
    }
    check_ids(feed_id, key_id)?;
    Ok(FeedKey {
        feed_id: feed_id.to_owned(),
        key_id: key_id.to_owned(),
        signing: SigningKey::from_bytes(&seed),
    })
}
