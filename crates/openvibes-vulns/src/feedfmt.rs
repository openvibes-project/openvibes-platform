//! Verifying a signed feed (openvibes-protocol `spec/feed-v1.md`): the
//! envelope, the Ed25519 signature, the manifest, time and sequence, and each
//! file's size and hash. Nothing here touches the network or the database.
//!
//! The order of the checks is the spec's, and the shared vectors in
//! `openvibes-protocol/vectors/feed-*.json` run against this code
//! (`tests/feed_vectors.rs`).

use std::collections::HashSet;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Largest `feed.json`, in bytes.
pub const MAX_ENVELOPE: usize = 1 << 20;
/// Most files in one manifest.
pub const MAX_FILES: usize = 64;
/// How far ahead of this clock a builder's `created_at` may be, in seconds.
pub const CREATED_SKEW: i64 = 600;
/// Latest time the format allows (year 2100).
const LATEST: i64 = 4_102_444_800;
const PREIMAGE_PREFIX: &[u8] = b"OPENVIBES-FEED-MANIFEST-V1\0";

/// Why a feed is refused. The strings are the spec's reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The envelope is oversized, unreadable, or not format 1.
    BadFormat,
    /// No key is trusted for this feed id and key id.
    UnknownKey,
    /// The signature does not verify.
    BadSignature,
    /// The signed manifest is unreadable or breaks a rule.
    BadManifest,
    /// `created_at` is more than 10 minutes ahead.
    NotYetValid,
    /// `expires_at` has passed.
    Expired,
    /// A lower sequence than already accepted.
    SequenceReplay,
    /// The same sequence with a different manifest.
    SequenceConflict,
}

impl Refusal {
    /// The reason as the spec and the vectors spell it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadFormat => "bad_format",
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::BadManifest => "bad_manifest",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::SequenceReplay => "sequence_replay",
            Self::SequenceConflict => "sequence_conflict",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadFormat => "not a readable feed (bad format)",
            Self::UnknownKey => "signed by a key this platform does not trust",
            Self::BadSignature => "the signature does not verify",
            Self::BadManifest => "the manifest is unreadable or breaks a rule",
            Self::NotYetValid => "created more than 10 minutes in the future",
            Self::Expired => "the feed has expired",
            Self::SequenceReplay => "older than a feed already accepted",
            Self::SequenceConflict => "same sequence as an accepted feed but different content",
        })
    }
}

/// A key a site trusts for one feed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedKey {
    /// The feed it may sign for.
    pub feed_id: String,
    /// Its id within the feed.
    pub key_id: String,
    /// The 32-byte public key.
    pub public_key: [u8; 32],
}

/// The highest manifest already accepted for one key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Applied {
    /// The feed.
    pub feed_id: String,
    /// The key.
    pub key_id: String,
    /// The accepted sequence.
    pub sequence: u64,
    /// SHA-256 of that manifest's signature preimage.
    pub manifest_digest: [u8; 32],
}

/// What a file contains, which says which importer reads it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Fedora `repomd.xml`.
    Repomd,
    /// Fedora `updateinfo.xml[.zst]`.
    Updateinfo,
    /// An OSV ecosystem `all.zip`.
    Osv,
    /// CISA KEV JSON.
    Kev,
    /// EPSS CSV.
    Epss,
    /// EUVD's exploited list.
    Euvd,
    /// Slim NVD, one year.
    Nvd,
}

impl Kind {
    /// The kind as the manifest spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Repomd => "repomd",
            Self::Updateinfo => "updateinfo",
            Self::Osv => "osv",
            Self::Kev => "kev",
            Self::Epss => "epss",
            Self::Euvd => "euvd",
            Self::Nvd => "nvd",
        }
    }

    /// The format's hard largest `size` for this kind.
    #[must_use]
    pub fn max_size(self) -> u64 {
        match self {
            Self::Repomd => 1 << 20,
            Self::Updateinfo => 256 << 20,
            Self::Osv => 8 << 30,
            Self::Kev | Self::Euvd => 64 << 20,
            Self::Epss => 128 << 20,
            Self::Nvd => 512 << 20,
        }
    }
}

/// One file the manifest names.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// The source (`kev`, `fedora-44-x86_64`, `ubuntu`, ...).
    pub source: String,
    /// What it contains.
    pub kind: Kind,
    /// A label for people.
    pub name: String,
    /// Lowercase hex SHA-256 of the blob; also the blob's name.
    pub sha256: String,
    /// The blob's length.
    pub size: u64,
    /// When the builder fetched it, Unix seconds.
    pub fetched_at: i64,
    /// Where it came from; never fetched.
    pub upstream: String,
    /// For `osv`: the platform sources the file feeds.
    #[serde(default)]
    pub releases: Option<Vec<String>>,
}

/// The signed manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Rises with every build.
    pub sequence: u64,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds.
    pub expires_at: i64,
    /// The files, 1 to 64.
    pub files: Vec<FileEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: u32,
    feed_id: String,
    key_id: String,
    signature: String,
    manifest: String,
}

/// A feed that passed every check up to the sequence.
#[derive(Clone, Debug)]
pub struct Accepted {
    /// The feed.
    pub feed_id: String,
    /// The key that signed it.
    pub key_id: String,
    /// The verified manifest.
    pub manifest: Manifest,
    /// SHA-256 of the signature preimage.
    pub digest: [u8; 32],
    /// The same sequence and digest were accepted before.
    pub repeat: bool,
}

/// Whether `text` is a feed or key id: 1 to 128 of `A-Za-z0-9._:-`.
#[must_use]
pub fn identifier(text: &str) -> bool {
    (1..=128).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Canonical unpadded base64url: re-encoding must give the same text.
fn canonical_b64(text: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    (URL_SAFE_NO_PAD.encode(&bytes) == text).then_some(bytes)
}

/// Decodes a public key given on a command line (canonical base64url, 32 bytes).
#[must_use]
pub fn parse_public_key(text: &str) -> Option<[u8; 32]> {
    let key: [u8; 32] = canonical_b64(text)?.try_into().ok()?;
    VerifyingKey::from_bytes(&key)
        .ok()
        .filter(|key| !key.is_weak())?;
    Some(key)
}

/// The key's fingerprint: the first 128 bits of the SHA-256 of the public
/// key, as 8 groups of 4 lowercase hex characters.
#[must_use]
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The bytes that are signed (spec "Signature preimage").
#[must_use]
pub fn preimage(feed_id: &str, key_id: &str, manifest: &str) -> Vec<u8> {
    let mut out = PREIMAGE_PREFIX.to_vec();
    out.extend_from_slice(&1u16.to_be_bytes());
    for text in [feed_id, key_id] {
        out.extend_from_slice(&u32::try_from(text.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(text.as_bytes());
    }
    out.extend_from_slice(&(manifest.len() as u64).to_be_bytes());
    out.extend_from_slice(manifest.as_bytes());
    out
}

fn hex_lower(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn within(time: i64) -> bool {
    (1..=LATEST).contains(&time)
}

fn source_fits(entry: &FileEntry) -> bool {
    let fedora = |source: &str| {
        let Some(rest) = source.strip_prefix("fedora-") else {
            return false;
        };
        let mut parts = rest.splitn(2, '-');
        let (release, arch) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        (1..=3).contains(&release.len())
            && release.bytes().all(|b| b.is_ascii_digit())
            && (1..=16).contains(&arch.len())
            && arch
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    match entry.kind {
        Kind::Repomd | Kind::Updateinfo => fedora(&entry.source),
        Kind::Osv => matches!(
            entry.source.as_str(),
            "debian" | "ubuntu" | "rocky-linux" | "almalinux"
        ),
        Kind::Kev => entry.source == "kev",
        Kind::Epss => entry.source == "epss",
        Kind::Euvd => entry.source == "euvd",
        Kind::Nvd => entry.source == "nvd",
    }
}

fn entry_ok(entry: &FileEntry) -> bool {
    let releases_ok = match (&entry.releases, entry.kind) {
        (Some(list), Kind::Osv) => {
            let unique: HashSet<&String> = list.iter().collect();
            (1..=64).contains(&list.len())
                && unique.len() == list.len()
                && list.iter().all(|release| {
                    (1..=32).contains(&release.len())
                        && release.bytes().all(|b| {
                            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-')
                        })
                })
        }
        (None, Kind::Osv) => false,
        (Some(_), _) => false,
        (None, _) => true,
    };
    releases_ok
        && source_fits(entry)
        && (1..=64).contains(&entry.name.len())
        && entry
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && hex_lower(&entry.sha256)
        && (1..=entry.kind.max_size()).contains(&entry.size)
        && within(entry.fetched_at)
        && entry.upstream.len() <= 2048
        && (entry.upstream.starts_with("https://") || entry.upstream.starts_with("http://"))
        && !entry.upstream.chars().any(char::is_control)
}

fn manifest_ok(manifest: &Manifest) -> bool {
    let mut seen = HashSet::new();
    manifest.sequence >= 1
        && within(manifest.created_at)
        && within(manifest.expires_at)
        && manifest.expires_at > manifest.created_at
        && (1..=MAX_FILES).contains(&manifest.files.len())
        && manifest
            .files
            .iter()
            .all(|file| entry_ok(file) && seen.insert((file.source.as_str(), file.name.as_str())))
}

/// Verifies `feed.json` in the spec's order and returns the verified
/// manifest. `trusted` are the keys the site trusts, `applied` the highest
/// accepted manifest per key, `now` Unix seconds.
///
/// # Errors
/// The first check that fails, as a [`Refusal`].
pub fn verify(
    bytes: &[u8],
    trusted: &[TrustedKey],
    applied: &[Applied],
    now: i64,
) -> Result<Accepted, Refusal> {
    if bytes.len() > MAX_ENVELOPE {
        return Err(Refusal::BadFormat);
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| Refusal::BadFormat)?;
    let signature = canonical_b64(&envelope.signature)
        .and_then(|raw| <[u8; 64]>::try_from(raw).ok())
        .ok_or(Refusal::BadFormat)?;
    if envelope.format != 1
        || !identifier(&envelope.feed_id)
        || !identifier(&envelope.key_id)
        || !(2..=MAX_ENVELOPE).contains(&envelope.manifest.chars().count())
    {
        return Err(Refusal::BadFormat);
    }
    let key = trusted
        .iter()
        .find(|key| key.feed_id == envelope.feed_id && key.key_id == envelope.key_id)
        .ok_or(Refusal::UnknownKey)?;
    let pre = preimage(&envelope.feed_id, &envelope.key_id, &envelope.manifest);
    let verifying = VerifyingKey::from_bytes(&key.public_key).map_err(|_| Refusal::BadSignature)?;
    if verifying.is_weak()
        || verifying
            .verify_strict(&pre, &Signature::from_bytes(&signature))
            .is_err()
    {
        return Err(Refusal::BadSignature);
    }
    let manifest: Manifest =
        serde_json::from_str(&envelope.manifest).map_err(|_| Refusal::BadManifest)?;
    if !manifest_ok(&manifest) {
        return Err(Refusal::BadManifest);
    }
    if manifest.created_at > now.saturating_add(CREATED_SKEW) {
        return Err(Refusal::NotYetValid);
    }
    if now >= manifest.expires_at {
        return Err(Refusal::Expired);
    }
    let digest: [u8; 32] = Sha256::digest(&pre).into();
    let mut repeat = false;
    if let Some(known) = applied
        .iter()
        .find(|known| known.feed_id == envelope.feed_id && known.key_id == envelope.key_id)
    {
        if manifest.sequence < known.sequence {
            return Err(Refusal::SequenceReplay);
        }
        if manifest.sequence == known.sequence {
            if digest != known.manifest_digest {
                return Err(Refusal::SequenceConflict);
            }
            repeat = true;
        }
    }
    Ok(Accepted {
        feed_id: envelope.feed_id,
        key_id: envelope.key_id,
        manifest,
        digest,
        repeat,
    })
}

/// Why a file is not applied (step 7 of the spec).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileRefusal {
    /// Over the reader's own size limit.
    TooLarge,
    /// The blob's length is not the manifest's.
    SizeMismatch,
    /// The blob's SHA-256 is not the manifest's.
    HashMismatch,
    /// The builder fetched it before the file applied last for this source.
    OlderThanApplied,
}

impl FileRefusal {
    /// The reason as the vectors spell it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::SizeMismatch => "size_mismatch",
            Self::HashMismatch => "hash_mismatch",
            Self::OlderThanApplied => "older_than_applied",
        }
    }
}

/// Checks one file's blob (its length and hex SHA-256 as measured) against
/// its entry. `applied_fetched_at` is the `fetched_at` last applied for the
/// same source and kind; `limit` is this reader's own largest file.
///
/// # Errors
/// The first failing check.
pub fn check_file(
    entry: &FileEntry,
    length: u64,
    sha256_hex: &str,
    applied_fetched_at: Option<i64>,
    limit: u64,
) -> Result<(), FileRefusal> {
    if entry.size > limit || length > limit {
        return Err(FileRefusal::TooLarge);
    }
    if length != entry.size {
        return Err(FileRefusal::SizeMismatch);
    }
    if sha256_hex != entry.sha256 {
        return Err(FileRefusal::HashMismatch);
    }
    if applied_fetched_at.is_some_and(|applied| entry.fetched_at < applied) {
        return Err(FileRefusal::OlderThanApplied);
    }
    Ok(())
}

/// Lowercase hex of a SHA-256 digest.
#[must_use]
pub fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
