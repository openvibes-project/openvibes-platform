//! Feed state: what each feed last delivered and when it was checked.

use chrono::{DateTime, Utc};

use crate::{Client, StoreError};

/// A feed's state after a check or import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedState {
    /// e.g. `fedora-44-x86_64`.
    pub source: String,
    /// e.g. `fedora`.
    pub os_id: String,
    /// e.g. `44`.
    pub os_version: String,
    /// e.g. `x86_64`.
    pub arch: String,
    /// Last check (download or import attempt).
    pub last_checked_at: Option<DateTime<Utc>>,
    /// Last time the content changed.
    pub last_changed_at: Option<DateTime<Utc>>,
    /// Advisories in the last good content.
    pub advisories: i32,
    /// Last error, cleared by a good check.
    pub last_error: Option<String>,
}

/// Records a check: `Ok((sha256, advisories))` for new good content, or an
/// error message (the previous content and advisories are kept).
pub async fn record_feed(
    client: &Client,
    source: (&str, &str, &str, &str),
    outcome: Result<([u8; 32], i32), &str>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let (source, os_id, os_version, arch) = source;
    match outcome {
        Ok((sha256, advisories)) => client
            .execute(
                "INSERT INTO feed_sources (source, os_id, os_version, arch, last_checked_at,
                     last_changed_at, content_sha256, advisories, last_error)
                 VALUES ($1, $2, $3, $4, $5, $5, $6, $7, NULL)
                 ON CONFLICT (source) DO UPDATE SET last_checked_at = $5,
                     last_changed_at = CASE WHEN feed_sources.content_sha256 IS DISTINCT FROM $6
                         THEN $5 ELSE feed_sources.last_changed_at END,
                     content_sha256 = $6, advisories = $7, last_error = NULL",
                &[&source, &os_id, &os_version, &arch, &now, &sha256.as_slice(), &advisories],
            )
            .await?,
        Err(error) => client
            .execute(
                "INSERT INTO feed_sources (source, os_id, os_version, arch, last_checked_at, last_error)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (source) DO UPDATE SET last_checked_at = $5, last_error = $6",
                &[&source, &os_id, &os_version, &arch, &now, &error],
            )
            .await?,
    };
    Ok(())
}

/// Every feed's state.
pub async fn feeds(client: &Client) -> Result<Vec<FeedState>, StoreError> {
    let rows = client
        .query(
            "SELECT source, os_id, os_version, arch, last_checked_at, last_changed_at,
                    advisories, last_error FROM feed_sources ORDER BY source",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| FeedState {
            source: row.get(0),
            os_id: row.get(1),
            os_version: row.get(2),
            arch: row.get(3),
            last_checked_at: row.get(4),
            last_changed_at: row.get(5),
            advisories: row.get(6),
            last_error: row.get(7),
        })
        .collect())
}

/// The digest of a feed's last good content, if any.
pub async fn feed_digest(client: &Client, source: &str) -> Result<Option<[u8; 32]>, StoreError> {
    let row = client
        .query_opt(
            "SELECT content_sha256 FROM feed_sources WHERE source = $1",
            &[&source],
        )
        .await?;
    Ok(row
        .and_then(|row| row.get::<_, Option<Vec<u8>>>(0))
        .and_then(|bytes| bytes.try_into().ok()))
}

/// The ETag a source last served with good content, if any.
pub async fn feed_etag(client: &Client, source: &str) -> Result<Option<String>, StoreError> {
    let row = client
        .query_opt(
            "SELECT etag FROM feed_sources WHERE source = $1",
            &[&source],
        )
        .await?;
    Ok(row.and_then(|row| row.get(0)))
}

/// Stores the ETag served with a source's current content.
pub async fn set_feed_etag(
    client: &Client,
    source: &str,
    etag: Option<&str>,
) -> Result<(), StoreError> {
    client
        .execute(
            "UPDATE feed_sources SET etag = $2 WHERE source = $1",
            &[&source, &etag],
        )
        .await?;
    Ok(())
}

/// Records a check that found the content unchanged.
pub async fn touch_feed(
    client: &Client,
    source: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    client
        .execute(
            "UPDATE feed_sources SET last_checked_at = $2, last_error = NULL WHERE source = $1",
            &[&source, &now],
        )
        .await?;
    Ok(())
}

/// The Fedora releases hosts report, e.g. `["43", "44"]`.
pub async fn fedora_releases(client: &Client) -> Result<Vec<String>, StoreError> {
    Ok(client
        .query(
            "SELECT DISTINCT os_version FROM agents WHERE os_id = 'fedora'
               AND os_version IS NOT NULL ORDER BY 1",
            &[],
        )
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect())
}
