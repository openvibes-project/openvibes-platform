//! Rule distribution: rule sets, their trusted signing keys, and published
//! envelopes. The admin role writes; `serve` runs within the
//! `openvibes_distribution` role's grants.

use chrono::{DateTime, Utc};

use crate::{Client, StoreError};

/// Advisory lock namespace for per-set publishing ("ovru").
const PUBLISH_LOCK: i32 = 0x6f76_7275;

/// A trusted Ed25519 key for one rule set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustKey {
    /// Rule set it may sign.
    pub rule_set_id: String,
    /// Issuer key id named in envelopes.
    pub issuer_key_id: String,
    /// Compressed Ed25519 public key.
    pub public_key: [u8; 32],
    /// When it was added.
    pub added_at: DateTime<Utc>,
    /// When it was removed; removed ids are never re-used.
    pub removed_at: Option<DateTime<Utc>>,
}

/// Outcome of [`add_trust_key`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustAdded {
    /// Newly trusted (the rule set is created if needed).
    Added,
    /// The same key is already trusted under this id.
    AlreadyTrusted,
    /// The id is taken by a different key, or was removed.
    Conflict,
    /// The rule set is retired.
    Retired,
}

/// A signed envelope to publish, already verified by the caller.
#[derive(Clone, Debug)]
pub struct NewBundle<'a> {
    /// Rule set it belongs to.
    pub rule_set_id: &'a str,
    /// Its `rule_set_version`.
    pub version: i64,
    /// The exact signed bytes.
    pub envelope: &'a [u8],
    /// SHA-256 of `envelope`.
    pub envelope_sha256: [u8; 32],
    /// Issuer that signed it.
    pub issuer_key_id: &'a str,
    /// Signed creation time.
    pub created_at_ms: i64,
    /// Signed expiry.
    pub expires_at_ms: i64,
    /// Operator who published it.
    pub published_by: &'a str,
}

/// Outcome of [`publish`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Published {
    /// Stored as the new current version.
    Stored,
    /// The same version with the same bytes is already stored.
    Unchanged,
    /// The same version is stored with different bytes.
    VersionConflict,
    /// The version is not above the current one (given).
    NotAboveCurrent(i64),
    /// The rule set is retired.
    Retired,
    /// No such rule set (it has never had a trusted key).
    UnknownSet,
}

/// A rule set as listed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleSetRow {
    /// Rule set id.
    pub rule_set_id: String,
    /// When it was created.
    pub created_at: DateTime<Utc>,
    /// When it was retired.
    pub retired_at: Option<DateTime<Utc>>,
    /// Highest published version.
    pub current_version: Option<i64>,
    /// Signed expiry of that version.
    pub current_expires_at_ms: Option<i64>,
    /// Keys currently trusted.
    pub trusted_keys: i64,
}

/// A published bundle's metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleRow {
    /// Version.
    pub version: i64,
    /// SHA-256 of the stored bytes.
    pub envelope_sha256: [u8; 32],
    /// Issuer that signed it.
    pub issuer_key_id: String,
    /// Signed creation time.
    pub created_at_ms: i64,
    /// Signed expiry.
    pub expires_at_ms: i64,
    /// When it was published.
    pub published_at: DateTime<Utc>,
    /// Who published it.
    pub published_by: String,
    /// Envelope size in bytes.
    pub bytes: i32,
}

/// What the distribution service answers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Served {
    /// Unknown or retired rule set, or nothing published: 404.
    Unknown,
    /// The agent's version is current or newer: 204.
    UpToDate,
    /// The current envelope, exactly as stored: 200.
    Envelope(Vec<u8>),
}

fn key32(bytes: &[u8]) -> Result<[u8; 32], StoreError> {
    bytes.try_into().map_err(|_| StoreError::Query)
}

/// Trusts `key` as `issuer` for `set`, creating the set if needed.
pub async fn add_trust_key(
    client: &Client,
    set: &str,
    issuer: &str,
    key: [u8; 32],
) -> Result<TrustAdded, StoreError> {
    client
        .execute(
            "INSERT INTO rule_sets (rule_set_id) VALUES ($1) ON CONFLICT DO NOTHING",
            &[&set],
        )
        .await?;
    let retired: bool = client
        .query_one(
            "SELECT retired_at IS NOT NULL FROM rule_sets WHERE rule_set_id = $1",
            &[&set],
        )
        .await?
        .get(0);
    if retired {
        return Ok(TrustAdded::Retired);
    }
    let inserted = client
        .execute(
            "INSERT INTO rule_trust_keys (rule_set_id, issuer_key_id, public_key) \
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            &[&set, &issuer, &key.as_slice()],
        )
        .await?;
    if inserted == 1 {
        return Ok(TrustAdded::Added);
    }
    let row = client
        .query_one(
            "SELECT public_key, removed_at IS NULL FROM rule_trust_keys \
             WHERE rule_set_id = $1 AND issuer_key_id = $2",
            &[&set, &issuer],
        )
        .await?;
    let (stored, active): (Vec<u8>, bool) = (row.get(0), row.get(1));
    Ok(if active && stored == key {
        TrustAdded::AlreadyTrusted
    } else {
        TrustAdded::Conflict
    })
}

/// Every trust key, or those of one set, removed ones included.
pub async fn trust_keys(client: &Client, set: Option<&str>) -> Result<Vec<TrustKey>, StoreError> {
    let rows = client
        .query(
            "SELECT rule_set_id, issuer_key_id, public_key, added_at, removed_at \
             FROM rule_trust_keys WHERE $1::text IS NULL OR rule_set_id = $1 \
             ORDER BY rule_set_id, issuer_key_id",
            &[&set],
        )
        .await?;
    rows.iter()
        .map(|row| {
            Ok(TrustKey {
                rule_set_id: row.get(0),
                issuer_key_id: row.get(1),
                public_key: key32(row.get(2))?,
                added_at: row.get(3),
                removed_at: row.get(4),
            })
        })
        .collect()
}

/// The keys currently trusted for `set`, as (public key, issuer key id).
pub async fn active_trust_keys(
    client: &Client,
    set: &str,
) -> Result<Vec<([u8; 32], String)>, StoreError> {
    let rows = client
        .query(
            "SELECT public_key, issuer_key_id FROM rule_trust_keys \
             WHERE rule_set_id = $1 AND removed_at IS NULL ORDER BY issuer_key_id",
            &[&set],
        )
        .await?;
    rows.iter()
        .map(|row| Ok((key32(row.get(0))?, row.get(1))))
        .collect()
}

/// Stops trusting a key; `false` if it was not trusted.
pub async fn remove_trust_key(
    client: &Client,
    set: &str,
    issuer: &str,
) -> Result<bool, StoreError> {
    let changed = client
        .execute(
            "UPDATE rule_trust_keys SET removed_at = now() \
             WHERE rule_set_id = $1 AND issuer_key_id = $2 AND removed_at IS NULL",
            &[&set, &issuer],
        )
        .await?;
    Ok(changed == 1)
}

/// Stores a verified envelope as the set's new current version.
pub async fn publish(client: &mut Client, bundle: &NewBundle<'_>) -> Result<Published, StoreError> {
    let transaction = client.transaction().await?;
    // Serializes publishers of one set, so check-then-insert is atomic.
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock($1, hashtext($2))",
            &[&PUBLISH_LOCK, &bundle.rule_set_id],
        )
        .await?;
    let Some(set) = transaction
        .query_opt(
            "SELECT retired_at IS NOT NULL FROM rule_sets WHERE rule_set_id = $1",
            &[&bundle.rule_set_id],
        )
        .await?
    else {
        return Ok(Published::UnknownSet);
    };
    if set.get::<_, bool>(0) {
        return Ok(Published::Retired);
    }
    if let Some(row) = transaction
        .query_opt(
            "SELECT envelope FROM rule_bundles WHERE rule_set_id = $1 AND version = $2",
            &[&bundle.rule_set_id, &bundle.version],
        )
        .await?
    {
        let stored: &[u8] = row.get(0);
        return Ok(if stored == bundle.envelope {
            Published::Unchanged
        } else {
            Published::VersionConflict
        });
    }
    let current: Option<i64> = transaction
        .query_one(
            "SELECT max(version) FROM rule_bundles WHERE rule_set_id = $1",
            &[&bundle.rule_set_id],
        )
        .await?
        .get(0);
    if let Some(current) = current.filter(|current| *current >= bundle.version) {
        return Ok(Published::NotAboveCurrent(current));
    }
    transaction
        .execute(
            "INSERT INTO rule_bundles (rule_set_id, version, envelope, envelope_sha256, \
             issuer_key_id, created_at_ms, expires_at_ms, published_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &bundle.rule_set_id,
                &bundle.version,
                &bundle.envelope,
                &bundle.envelope_sha256.as_slice(),
                &bundle.issuer_key_id,
                &bundle.created_at_ms,
                &bundle.expires_at_ms,
                &bundle.published_by,
            ],
        )
        .await?;
    transaction.commit().await?;
    Ok(Published::Stored)
}

/// Every rule set with its current version and trusted key count.
pub async fn list(client: &Client) -> Result<Vec<RuleSetRow>, StoreError> {
    let rows = client
        .query(
            "SELECT s.rule_set_id, s.created_at, s.retired_at, b.version, b.expires_at_ms, \
             (SELECT count(*) FROM rule_trust_keys k \
              WHERE k.rule_set_id = s.rule_set_id AND k.removed_at IS NULL) \
             FROM rule_sets s LEFT JOIN LATERAL (SELECT version, expires_at_ms \
              FROM rule_bundles WHERE rule_set_id = s.rule_set_id \
              ORDER BY version DESC LIMIT 1) b ON true \
             ORDER BY s.rule_set_id",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| RuleSetRow {
            rule_set_id: row.get(0),
            created_at: row.get(1),
            retired_at: row.get(2),
            current_version: row.get(3),
            current_expires_at_ms: row.get(4),
            trusted_keys: row.get(5),
        })
        .collect())
}

/// A set's published bundles, newest first.
pub async fn bundles(client: &Client, set: &str) -> Result<Vec<BundleRow>, StoreError> {
    let rows = client
        .query(
            "SELECT version, envelope_sha256, issuer_key_id, created_at_ms, expires_at_ms, \
             published_at, published_by, length(envelope) \
             FROM rule_bundles WHERE rule_set_id = $1 ORDER BY version DESC",
            &[&set],
        )
        .await?;
    rows.iter()
        .map(|row| {
            Ok(BundleRow {
                version: row.get(0),
                envelope_sha256: key32(row.get(1))?,
                issuer_key_id: row.get(2),
                created_at_ms: row.get(3),
                expires_at_ms: row.get(4),
                published_at: row.get(5),
                published_by: row.get(6),
                bytes: row.get(7),
            })
        })
        .collect()
}

/// Retires a set: it is no longer served or published to. Its bundles stay
/// for audit. `false` if it is unknown or already retired.
pub async fn retire(client: &Client, set: &str) -> Result<bool, StoreError> {
    let changed = client
        .execute(
            "UPDATE rule_sets SET retired_at = now() \
             WHERE rule_set_id = $1 AND retired_at IS NULL",
            &[&set],
        )
        .await?;
    Ok(changed == 1)
}

/// One indexed query (the primary key, read backwards): the highest version
/// of a live set, with its bytes only when the agent's version is older.
pub async fn serve(client: &Client, set: &str, current: Option<i64>) -> Result<Served, StoreError> {
    let row = client
        .query_opt(
            "SELECT CASE WHEN b.version > $2 THEN b.envelope END FROM rule_bundles b \
             JOIN rule_sets s USING (rule_set_id) \
             WHERE b.rule_set_id = $1 AND s.retired_at IS NULL \
             ORDER BY b.version DESC LIMIT 1",
            &[&set, &current.unwrap_or(0)],
        )
        .await?;
    Ok(match row {
        None => Served::Unknown,
        Some(row) => row
            .get::<_, Option<Vec<u8>>>(0)
            .map_or(Served::UpToDate, Served::Envelope),
    })
}
