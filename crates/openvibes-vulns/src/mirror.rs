//! Reading a feed mirror (openvibes-protocol `spec/feed-v1.md`): every check
//! interval `feed.json` is fetched from the address the administrator set,
//! verified with the code a bundle uses, and only the files whose SHA-256
//! differs from what is applied are downloaded, into a private folder that is
//! deleted afterwards. The result goes to [`feedimport::apply`] with origin
//! `mirror`. Nothing here falls back to the internet: an unreachable or
//! refused mirror leaves the old data serving and records the reason on the
//! `mirror` row of the feed status.
//!
//! Trust is the address (spec "Pinning"): the first key the mirror presents
//! is pinned once its signature verifies, and a different key later is
//! refused.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use platform_store::{Client, audit, feeds, vulns};

use crate::{
    bundle::Unpacked,
    feedfmt::{self, Accepted, Applied, FileEntry, MAX_ENVELOPE, Peek, TrustedKey},
    feedimport::{self, BLOB_MISSING, Outcome},
    fetch::Fetcher,
};

/// The feed-status row of the mirror: `(source, os_id, os_version, arch)`.
pub const STATUS: (&str, &str, &str, &str) = ("mirror", "mirror", "", "");

/// What one check did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Synced {
    /// Nothing new: the same feed, or one whose files are all applied.
    Unchanged,
    /// A feed was applied; the counts are files.
    Applied {
        /// Its sequence.
        sequence: u64,
        /// Files applied now.
        applied: usize,
        /// Files not applied.
        refused: usize,
    },
}

/// A mirror being read: where, how, and what the last check saw.
pub struct Mirror {
    fetcher: Fetcher,
    base: String,
    work: PathBuf,
    etag: Option<String>,
    last_body: Option<Vec<u8>>,
    last_audit: Option<String>,
    files: i32,
    digest: [u8; 32],
}

impl Mirror {
    /// Forgets the last feed seen, so the next check reads it again.
    pub fn forget(&mut self) {
        self.etag = None;
        self.last_body = None;
    }

    /// A mirror at `base` (its `feed.json` and `blobs/` are below it), with
    /// `work` as the folder private copies are made in.
    #[must_use]
    pub fn new(fetcher: Fetcher, base: &str, work: &Path) -> Self {
        Self {
            fetcher,
            base: base.trim_end_matches('/').to_owned(),
            work: work.to_owned(),
            etag: None,
            last_body: None,
            last_audit: None,
            files: 0,
            digest: [0; 32],
        }
    }
}

/// Which keys to verify with, and the one to pin if the feed verifies.
struct Plan {
    keys: Vec<TrustedKey>,
    pin: Option<TrustedKey>,
}

fn fingerprint(key: &[u8; 32]) -> String {
    feedfmt::fingerprint(key)
}

/// Decides what the mirror's `feed.json` may be verified with (spec
/// "Pinning"). `keys` are the active keys and whether each was pinned.
fn plan(peek: Option<&Peek>, keys: &[(TrustedKey, bool)]) -> Result<Plan, String> {
    let trusted: Vec<TrustedKey> = keys.iter().map(|(key, _)| key.clone()).collect();
    let plain = |keys| Plan { keys, pin: None };
    let Some(peek) = peek else {
        return Ok(plain(trusted));
    };
    let name = format!("{}/{}", peek.feed_id, peek.key_id);
    if let Some(known) = trusted
        .iter()
        .find(|key| key.feed_id == peek.feed_id && key.key_id == peek.key_id)
    {
        return match peek.public_key {
            Some(offered) if offered != known.public_key => Err(format!(
                "the mirror now offers another key for {name} (fingerprint {}), but this site \
                 trusts {}; the feed is refused. If the key was changed on purpose, remove the pinned key \
with `openvibes-admin feeds trust remove` and give the mirror's new key a new key id",
                fingerprint(&offered),
                fingerprint(&known.public_key)
            )),
            _ => Ok(plain(trusted)),
        };
    }
    if let Some((pinned, _)) = keys.iter().find(|(_, pinned)| *pinned) {
        return Err(format!(
            "the mirror signs as {name}, but this site pinned {}/{} (fingerprint {}); the feed \
             is refused",
            pinned.feed_id,
            pinned.key_id,
            fingerprint(&pinned.public_key)
        ));
    }
    if trusted.iter().any(|key| key.feed_id == peek.feed_id) {
        // An administrator trusts other keys of this feed: a new key id is
        // theirs to add, never pinned over.
        return Ok(plain(trusted));
    }
    match peek.public_key {
        Some(offered) => {
            let key = TrustedKey {
                feed_id: peek.feed_id.clone(),
                key_id: peek.key_id.clone(),
                public_key: offered,
            };
            let mut with = trusted;
            with.push(key.clone());
            Ok(Plan {
                keys: with,
                pin: Some(key),
            })
        }
        None => Err(format!(
            "the mirror's feed.json carries no public key and none is trusted for {name}: \
             update the mirror, or run `openvibes-admin feeds trust add`"
        )),
    }
}

/// OSV files none of the hosts' releases appear in: the importer reads them
/// and applies nothing, so downloading them is wasted.
async fn idle_osv(client: &Client, accepted: &Accepted) -> Vec<(String, String)> {
    let hosts: Vec<crate::osv::Release> = crate::osv_fetch::releases_by_ecosystem(client)
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "cannot list OSV releases; their files are not downloaded");
            Vec::new()
        })
        .into_iter()
        .flat_map(|(_, releases)| releases)
        .collect();
    accepted
        .manifest
        .files
        .iter()
        .filter(|entry| entry.kind == feedfmt::Kind::Osv)
        .filter(|entry| {
            !entry
                .releases
                .iter()
                .flatten()
                .filter_map(|name| name.parse::<crate::osv::Release>().ok())
                .any(|release| hosts.contains(&release))
        })
        .map(|entry| (entry.source.clone(), entry.name.clone()))
        .collect()
}

fn entry_key(entry: &FileEntry) -> (String, String, String) {
    (
        entry.source.clone(),
        entry.kind.as_str().to_owned(),
        entry.name.clone(),
    )
}

/// A private folder, removed when dropped.
struct Work(PathBuf);

impl Work {
    fn new(root: &Path) -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::create_dir_all(root)
            .map_err(|e| format!("cannot make {}: {e}", root.display()))?;
        // Left over from a crash.
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with("mirror-") {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = root.join(format!("mirror-{}-{nanos}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| format!("cannot make a work folder: {e}"))?;
        Ok(Self(dir))
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn download(
    fetcher: &Fetcher,
    base: &str,
    work: &Path,
    entries: &[&FileEntry],
) -> Vec<String> {
    let mut failures = Vec::new();
    for entry in entries {
        let (fetcher, url, path) = (
            fetcher.clone(),
            format!("{base}/blobs/{}", entry.sha256),
            work.join(&entry.sha256),
        );
        // One byte of room: a longer file then fails the length check below.
        let (limit, want, size) = (
            entry.size.saturating_add(1),
            entry.sha256.clone(),
            entry.size,
        );
        let target = path.clone();
        let got = tokio::task::spawn_blocking(move || {
            let digest = fetcher.download_to(&url, &target, limit)?;
            let length = std::fs::metadata(&target).map_or(0, |m| m.len());
            if feedfmt::hex(&digest) != want || length != size {
                return Err("the file does not match the feed".to_owned());
            }
            Ok(())
        })
        .await
        .unwrap_or_else(|_| Err("download task failed".to_owned()));
        if let Err(error) = got {
            let _ = std::fs::remove_file(&path);
            failures.push(format!("{} {}: {error}", entry.source, entry.name));
        }
    }
    failures
}

fn changed<'a>(
    accepted: &'a Accepted,
    applied: &HashMap<(String, String, String), [u8; 32]>,
) -> Vec<&'a FileEntry> {
    accepted
        .manifest
        .files
        .iter()
        .filter(|entry| {
            applied
                .get(&entry_key(entry))
                .is_none_or(|sha| feedfmt::hex(sha) != entry.sha256)
        })
        .collect()
}

async fn status_error(client: &Client, message: &str, now: DateTime<Utc>) {
    let _ = vulns::record_feed(client, STATUS, Err(message), now).await;
}

/// The refused feed or error, once per distinct text, in the audit log.
async fn audit_refusal(mirror: &mut Mirror, client: &Client, message: &str) {
    if mirror.last_audit.as_deref() == Some(message) {
        return;
    }
    mirror.last_audit = Some(message.to_owned());
    let _ = audit::record(
        client,
        "openvibes-vulns",
        "feeds.mirror_refused",
        Some(&mirror.base),
        &message.chars().take(300).collect::<String>(),
    )
    .await;
}

/// One check of the mirror. An `Err` is also on the `mirror` status row; the
/// data already applied keeps serving.
///
/// # Errors
/// The mirror cannot be read, its feed is refused, or a file failed.
pub async fn sync(
    client: &mut Client,
    mirror: &mut Mirror,
    now: DateTime<Utc>,
) -> Result<Synced, String> {
    match check(client, mirror, now).await {
        Ok(synced) => {
            mirror.last_audit = None;
            Ok(synced)
        }
        Err(message) => {
            status_error(client, &message, now).await;
            audit_refusal(mirror, client, &message).await;
            Err(message)
        }
    }
}

async fn check(
    client: &mut Client,
    mirror: &mut Mirror,
    now: DateTime<Utc>,
) -> Result<Synced, String> {
    let (fetcher, url, etag) = (
        mirror.fetcher.clone(),
        format!("{}/feed.json", mirror.base),
        mirror.etag.clone(),
    );
    let fetched = tokio::task::spawn_blocking(move || {
        fetcher.get_if_changed_up_to(&url, etag.as_deref(), MAX_ENVELOPE as u64 + 1)
    })
    .await
    .map_err(|_| "download task failed".to_owned())??;
    let (body, etag) = match fetched {
        None => return unchanged(client, mirror, now).await,
        Some((body, _)) if mirror.last_body.as_deref() == Some(body.as_slice()) => {
            return unchanged(client, mirror, now).await;
        }
        Some(got) => got,
    };
    let keys = feeds::trust_keys(client, None)
        .await
        .map_err(|e| e.to_string())?;
    let keys: Vec<(TrustedKey, bool)> = keys
        .into_iter()
        .filter(|key| key.removed_at.is_none())
        .map(|key| {
            (
                TrustedKey {
                    feed_id: key.feed_id,
                    key_id: key.key_id,
                    public_key: key.public_key,
                },
                key.pinned,
            )
        })
        .collect();
    let states: Vec<Applied> = feeds::feed_states(client)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|state| Applied {
            feed_id: state.feed_id,
            key_id: state.key_id,
            sequence: state.sequence,
            manifest_digest: state.manifest_digest,
        })
        .collect();
    let plan = plan(feedfmt::peek(&body).as_ref(), &keys)?;
    let accepted = feedfmt::verify(&body, &plan.keys, &states, now.timestamp())
        .map_err(|why| format!("the mirror's feed is refused: {} ({why})", why.as_str()))?;
    if let Some(key) = &plan.pin {
        let pinned = feeds::pin_trust_key(client, &key.feed_id, &key.key_id, key.public_key, now)
            .await
            .map_err(|e| e.to_string())?;
        if !pinned {
            return Err("the key could not be pinned; the feed is refused".into());
        }
        let _ = audit::record(
            client,
            "openvibes-vulns",
            "feeds.mirror_pin",
            Some(&format!(
                "{}/{} {}",
                key.feed_id,
                key.key_id,
                fingerprint(&key.public_key)
            )),
            "ok",
        )
        .await;
        tracing::info!(feed = %key.feed_id, key = %key.key_id, "pinned the mirror's key");
    }
    let applied: HashMap<_, _> = feeds::applied_files(client)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|file| ((file.source, file.kind, file.name), file.sha256))
        .collect();
    let idle = idle_osv(client, &accepted).await;
    let is_idle = |entry: &FileEntry| idle.contains(&(entry.source.clone(), entry.name.clone()));
    let wanted: Vec<&FileEntry> = changed(&accepted, &applied)
        .into_iter()
        .filter(|entry| !is_idle(entry))
        .collect();
    // An updateinfo is checked against its repomd.xml, which is applied on
    // its own: fetch the pair, so one failed updateinfo can be retried.
    let pairs: Vec<&FileEntry> = accepted
        .manifest
        .files
        .iter()
        .filter(|f| {
            f.kind == feedfmt::Kind::Repomd
                && wanted
                    .iter()
                    .any(|w| w.kind == feedfmt::Kind::Updateinfo && w.source == f.source)
                && !wanted.iter().any(|w| std::ptr::eq(*w, *f))
        })
        .collect();
    let wanted: Vec<&FileEntry> = wanted.into_iter().chain(pairs).collect();
    let label = format!(
        "{}/{} #{}",
        accepted.feed_id, accepted.key_id, accepted.manifest.sequence
    );
    if accepted.repeat && wanted.is_empty() {
        mirror.etag = etag;
        mirror.last_body = Some(body);
        return unchanged(client, mirror, now).await;
    }
    let work = Work::new(&mirror.work)?;
    let mut problems = download(&mirror.fetcher, &mirror.base, &work.0, &wanted).await;
    let unpacked = Unpacked {
        envelope: body.clone(),
        blobs: work.0.clone(),
        partial: true,
    };
    let mut reports = feedimport::apply(client, &unpacked, &accepted, "mirror", &[], now).await?;
    // A file whose hash did not change can still need reading (the NVD files
    // after new advisories): fetch what the importer asked for and go again.
    let missing: Vec<&FileEntry> = accepted
        .manifest
        .files
        .iter()
        .filter(|entry| {
            reports.iter().any(|r| {
                r.source == entry.source
                    && r.name == entry.name
                    && r.kind == entry.kind
                    && matches!(&r.outcome, Outcome::Refused(why) if why == BLOB_MISSING)
            })
        })
        .collect();
    let missing: Vec<&FileEntry> = missing
        .into_iter()
        .filter(|entry| !is_idle(entry) && !wanted.iter().any(|w| std::ptr::eq(*w, *entry)))
        .collect();
    if !missing.is_empty() {
        problems.extend(download(&mirror.fetcher, &mirror.base, &work.0, &missing).await);
        reports = feedimport::apply(client, &unpacked, &accepted, "mirror", &[], now).await?;
    }
    drop(work);
    let count = |keep: fn(&Outcome) -> bool| reports.iter().filter(|r| keep(&r.outcome)).count();
    let applied_now = count(|o| matches!(o, Outcome::Applied(_)));
    let not_read = |r: &feedimport::FileReport| {
        matches!(&r.outcome, Outcome::Refused(why) if why == BLOB_MISSING)
            && idle.contains(&(r.source.clone(), r.name.clone()))
    };
    let refused = reports
        .iter()
        .filter(|r| matches!(r.outcome, Outcome::Refused(_)) && !not_read(r))
        .count();
    for report in reports.iter().filter(|r| !not_read(r)) {
        if let Outcome::Refused(why) = &report.outcome
            && (why != BLOB_MISSING || problems.is_empty())
        {
            problems.push(format!("{} {}: {why}", report.source, report.name));
        }
    }
    let _ = audit::record(
        client,
        "openvibes-vulns",
        "feeds.mirror_apply",
        Some(&label),
        &format!("applied {applied_now} refused {refused}"),
    )
    .await;
    mirror.digest = accepted.digest;
    mirror.files = i32::try_from(accepted.manifest.files.len()).unwrap_or(i32::MAX);
    if problems.is_empty() {
        mirror.etag = etag;
        mirror.last_body = Some(body);
        vulns::record_feed(client, STATUS, Ok((mirror.digest, mirror.files)), now)
            .await
            .map_err(|e| e.to_string())?;
        tracing::info!(feed = %label, applied = applied_now, "mirror feed applied");
        return Ok(Synced::Applied {
            sequence: accepted.manifest.sequence,
            applied: applied_now,
            refused,
        });
    }
    // Tried again at the next check; what did apply stays applied.
    problems.truncate(5);
    Err(format!("{label}: {}", problems.join("; ")))
}

async fn unchanged(
    client: &mut Client,
    mirror: &mut Mirror,
    now: DateTime<Utc>,
) -> Result<Synced, String> {
    let Some(state) = feeds::feed_states(client)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|state| state.origin == "mirror")
        .max_by_key(|state| state.applied_at)
    else {
        return Ok(Synced::Unchanged);
    };
    // The same feed.json served again does not make old data fresh.
    if state.expires_at <= now {
        return Err(format!(
            "the mirror's feed expired at {}; the data is from {}. The mirror's build has \
             stopped, or its clock is wrong",
            state.expires_at.format("%Y-%m-%d %H:%M UTC"),
            state.created_at.format("%Y-%m-%d %H:%M UTC")
        ));
    }
    if mirror.digest == [0; 32] {
        mirror.digest = state.manifest_digest;
    }
    vulns::record_feed(client, STATUS, Ok((mirror.digest, mirror.files)), now)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Synced::Unchanged)
}

/// Marks each Fedora release hosts run that the mirror's feed does not carry,
/// so the status says what to add on the mirror.
pub async fn flag_missing_releases(client: &Client, arch: &str, now: DateTime<Utc>) {
    let Ok(releases) = vulns::fedora_releases(client).await else {
        return;
    };
    let Ok(files) = feeds::applied_files(client).await else {
        return;
    };
    for release in releases {
        let source = format!("fedora-{release}-{arch}");
        if files.iter().any(|file| file.source == source) {
            continue;
        }
        let message = format!("no data from the mirror for Fedora {release}; add it on the mirror");
        let _ = vulns::record_feed(
            client,
            (&source, "fedora", &release, arch),
            Err(&message),
            now,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(feed: &str, id: &str, byte: u8) -> TrustedKey {
        TrustedKey {
            feed_id: feed.into(),
            key_id: id.into(),
            public_key: [byte; 32],
        }
    }

    fn peek(feed: &str, id: &str, byte: Option<u8>) -> Peek {
        Peek {
            feed_id: feed.into(),
            key_id: id.into(),
            public_key: byte.map(|b| [b; 32]),
        }
    }

    #[test]
    fn the_first_key_is_pinned_when_nothing_is_trusted() {
        let plan = plan(Some(&peek("a", "k1", Some(1))), &[]).unwrap();
        assert_eq!(plan.pin.as_ref().map(|k| k.key_id.as_str()), Some("k1"));
        assert_eq!(plan.keys.len(), 1);
    }

    #[test]
    fn a_feed_without_a_key_cannot_be_pinned() {
        assert!(plan(Some(&peek("a", "k1", None)), &[]).is_err());
    }

    #[test]
    fn a_changed_key_under_a_trusted_id_is_refused() {
        let keys = [(key("a", "k1", 1), true)];
        let error = plan(Some(&peek("a", "k1", Some(2))), &keys).err().unwrap();
        assert!(error.contains("another key"), "{error}");
        assert!(
            plan(Some(&peek("a", "k1", Some(1))), &keys)
                .unwrap()
                .pin
                .is_none()
        );
        assert!(
            plan(Some(&peek("a", "k1", None)), &keys)
                .unwrap()
                .pin
                .is_none()
        );
    }

    #[test]
    fn nothing_is_pinned_over_a_pinned_key() {
        let keys = [(key("a", "k1", 1), true)];
        assert!(plan(Some(&peek("a", "k2", Some(2))), &keys).is_err());
        assert!(plan(Some(&peek("b", "k1", Some(2))), &keys).is_err());
    }

    #[test]
    fn nothing_is_pinned_in_a_feed_an_administrator_trusts() {
        let keys = [(key("a", "k1", 1), false)];
        let plan = plan(Some(&peek("a", "k2", Some(2))), &keys).unwrap();
        assert!(plan.pin.is_none());
        // Another feed id is a first contact.
        let other = super::plan(Some(&peek("b", "k1", Some(2))), &keys).unwrap();
        assert!(other.pin.is_some());
    }
}
