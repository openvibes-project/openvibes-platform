//! Signed vulnerability-data feeds (openvibes-protocol `spec/feed-v1.md`):
//! the keys a site trusts per feed, the highest sequence accepted per key,
//! and the last file applied per source and kind. The admin role writes the
//! keys; the vulnerability service keeps the state current.

use chrono::{DateTime, Utc};

use crate::{Client, StoreError};

fn key32(bytes: &[u8]) -> Result<[u8; 32], StoreError> {
    bytes.try_into().map_err(|_| StoreError::Query)
}

/// A trusted Ed25519 key for one feed.
#[derive(Clone, Debug)]
pub struct TrustKey {
    /// The feed the key may sign for.
    pub feed_id: String,
    /// The key's id within the feed.
    pub key_id: String,
    /// The 32-byte public key.
    pub public_key: [u8; 32],
    /// When it was added.
    pub added_at: DateTime<Utc>,
    /// When it stopped being trusted, if it has.
    pub removed_at: Option<DateTime<Utc>>,
}

/// Outcome of [`add_trust_key`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustAdded {
    /// Newly trusted.
    Added,
    /// The same key is already trusted under this id.
    AlreadyTrusted,
    /// The id was used before for a different key, or the same key was
    /// removed: ids are never re-used.
    Conflict,
}

/// Trusts `key` as `key_id` for `feed_id`.
pub async fn add_trust_key(
    client: &Client,
    feed_id: &str,
    key_id: &str,
    key: [u8; 32],
    now: DateTime<Utc>,
) -> Result<TrustAdded, StoreError> {
    let inserted = client
        .execute(
            "INSERT INTO feed_trust_keys (feed_id, key_id, public_key, added_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            &[&feed_id, &key_id, &key.as_slice(), &now],
        )
        .await?;
    if inserted == 1 {
        return Ok(TrustAdded::Added);
    }
    let row = client
        .query_one(
            "SELECT public_key, removed_at IS NULL FROM feed_trust_keys \
             WHERE feed_id = $1 AND key_id = $2",
            &[&feed_id, &key_id],
        )
        .await?;
    let (stored, active): (Vec<u8>, bool) = (row.get(0), row.get(1));
    Ok(if active && stored == key {
        TrustAdded::AlreadyTrusted
    } else {
        TrustAdded::Conflict
    })
}

/// Every trust key, or those of one feed, removed ones included.
pub async fn trust_keys(
    client: &Client,
    feed_id: Option<&str>,
) -> Result<Vec<TrustKey>, StoreError> {
    let rows = client
        .query(
            "SELECT feed_id, key_id, public_key, added_at, removed_at \
             FROM feed_trust_keys WHERE $1::text IS NULL OR feed_id = $1 \
             ORDER BY feed_id, key_id",
            &[&feed_id],
        )
        .await?;
    rows.iter()
        .map(|row| {
            Ok(TrustKey {
                feed_id: row.get(0),
                key_id: row.get(1),
                public_key: key32(row.get(2))?,
                added_at: row.get(3),
                removed_at: row.get(4),
            })
        })
        .collect()
}

/// The keys currently trusted, as (feed id, key id, public key).
pub async fn active_trust_keys(
    client: &Client,
) -> Result<Vec<(String, String, [u8; 32])>, StoreError> {
    let rows = client
        .query(
            "SELECT feed_id, key_id, public_key FROM feed_trust_keys \
             WHERE removed_at IS NULL ORDER BY feed_id, key_id",
            &[],
        )
        .await?;
    rows.iter()
        .map(|row| Ok((row.get(0), row.get(1), key32(row.get(2))?)))
        .collect()
}

/// Stops trusting a key; `false` if it was not trusted.
pub async fn remove_trust_key(
    client: &Client,
    feed_id: &str,
    key_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let changed = client
        .execute(
            "UPDATE feed_trust_keys SET removed_at = $3 \
             WHERE feed_id = $1 AND key_id = $2 AND removed_at IS NULL",
            &[&feed_id, &key_id, &now],
        )
        .await?;
    Ok(changed == 1)
}

/// The highest manifest accepted for one key.
#[derive(Clone, Debug)]
pub struct FeedState {
    /// The feed.
    pub feed_id: String,
    /// The key that signed it.
    pub key_id: String,
    /// The accepted sequence.
    pub sequence: u64,
    /// SHA-256 of that manifest's signature preimage.
    pub manifest_digest: [u8; 32],
    /// The manifest's `created_at`.
    pub created_at: DateTime<Utc>,
    /// The manifest's `expires_at`.
    pub expires_at: DateTime<Utc>,
    /// When it was accepted here.
    pub applied_at: DateTime<Utc>,
    /// `mirror` or `bundle`.
    pub origin: String,
}

/// Every key's accepted state.
pub async fn feed_states(client: &Client) -> Result<Vec<FeedState>, StoreError> {
    let rows = client
        .query(
            "SELECT feed_id, key_id, sequence, manifest_digest, created_at, expires_at, \
                    applied_at, origin FROM feed_state ORDER BY feed_id, key_id",
            &[],
        )
        .await?;
    rows.iter()
        .map(|row| {
            let sequence: i64 = row.get(2);
            Ok(FeedState {
                feed_id: row.get(0),
                key_id: row.get(1),
                sequence: u64::try_from(sequence).map_err(|_| StoreError::Query)?,
                manifest_digest: key32(row.get(3))?,
                created_at: row.get(4),
                expires_at: row.get(5),
                applied_at: row.get(6),
                origin: row.get(7),
            })
        })
        .collect()
}

/// A manifest to record as accepted.
#[derive(Clone, Debug)]
pub struct Accepted<'a> {
    /// The feed.
    pub feed_id: &'a str,
    /// The key that signed it.
    pub key_id: &'a str,
    /// Its sequence.
    pub sequence: u64,
    /// SHA-256 of its signature preimage.
    pub manifest_digest: [u8; 32],
    /// `created_at`.
    pub created_at: DateTime<Utc>,
    /// `expires_at`.
    pub expires_at: DateTime<Utc>,
    /// `mirror` or `bundle`.
    pub origin: &'a str,
}

/// Records a manifest as accepted. A lower sequence than the stored one, or
/// an equal one with a different digest, changes nothing (`false`); the same
/// manifest again only refreshes the time.
pub async fn record_accepted(
    client: &Client,
    accepted: &Accepted<'_>,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let sequence = i64::try_from(accepted.sequence).map_err(|_| StoreError::Query)?;
    let changed = client
        .execute(
            "INSERT INTO feed_state (feed_id, key_id, sequence, manifest_digest, created_at, \
                                     expires_at, applied_at, origin) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (feed_id, key_id) DO UPDATE SET \
                 sequence = EXCLUDED.sequence, manifest_digest = EXCLUDED.manifest_digest, \
                 created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at, \
                 applied_at = EXCLUDED.applied_at, origin = EXCLUDED.origin \
             WHERE feed_state.sequence < EXCLUDED.sequence \
                OR (feed_state.sequence = EXCLUDED.sequence \
                    AND feed_state.manifest_digest = EXCLUDED.manifest_digest)",
            &[
                &accepted.feed_id,
                &accepted.key_id,
                &sequence,
                &accepted.manifest_digest.as_slice(),
                &accepted.created_at,
                &accepted.expires_at,
                &now,
                &accepted.origin,
            ],
        )
        .await?;
    Ok(changed == 1)
}

/// The last file applied for a source, kind and name.
#[derive(Clone, Debug)]
pub struct AppliedFile {
    /// The source (`kev`, `fedora-44-x86_64`, ...).
    pub source: String,
    /// The file kind.
    pub kind: String,
    /// The file's name in the manifest.
    pub name: String,
    /// Its SHA-256.
    pub sha256: [u8; 32],
    /// When the builder fetched it.
    pub fetched_at: DateTime<Utc>,
}

/// Every applied file.
pub async fn applied_files(client: &Client) -> Result<Vec<AppliedFile>, StoreError> {
    let rows = client
        .query(
            "SELECT source, kind, name, sha256, fetched_at FROM feed_applied_files \
             ORDER BY source, kind, name",
            &[],
        )
        .await?;
    rows.iter()
        .map(|row| {
            Ok(AppliedFile {
                source: row.get(0),
                kind: row.get(1),
                name: row.get(2),
                sha256: key32(row.get(3))?,
                fetched_at: row.get(4),
            })
        })
        .collect()
}

/// Records a file as applied, from the manifest that carried it. An older
/// `fetched_at` than the stored one changes nothing (`false`).
pub async fn record_file(
    client: &Client,
    file: &AppliedFile,
    feed_id: &str,
    key_id: &str,
    sequence: u64,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let sequence = i64::try_from(sequence).map_err(|_| StoreError::Query)?;
    let changed = client
        .execute(
            "INSERT INTO feed_applied_files (source, kind, name, sha256, fetched_at, feed_id, key_id, \
                                             sequence, applied_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (source, kind, name) DO UPDATE SET \
                 sha256 = EXCLUDED.sha256, fetched_at = EXCLUDED.fetched_at, \
                 feed_id = EXCLUDED.feed_id, key_id = EXCLUDED.key_id, \
                 sequence = EXCLUDED.sequence, applied_at = EXCLUDED.applied_at \
             WHERE feed_applied_files.fetched_at <= EXCLUDED.fetched_at",
            &[
                &file.source,
                &file.kind,
                &file.name,
                &file.sha256.as_slice(),
                &file.fetched_at,
                &feed_id,
                &key_id,
                &sequence,
                &now,
            ],
        )
        .await?;
    Ok(changed == 1)
}
