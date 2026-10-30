//! `feeds trust …`, `feeds import-bundle` and `feeds applied`: signed
//! vulnerability-data feeds (openvibes-protocol `spec/feed-v1.md`).

use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use openvibes_vulns::{
    bundle,
    feedfmt::{self, Applied, TrustedKey},
    feedimport::{self, FileReport, Outcome},
};
use platform_store::feeds::{self, TrustAdded};

use super::TrustCommand;

fn store(error: platform_store::StoreError) -> String {
    error.to_string()
}

fn time(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn identifier(value: &str, what: &str) -> Result<(), String> {
    feedfmt::identifier(value)
        .then_some(())
        .ok_or_else(|| format!("invalid {what} (1 to 128 of letters, digits, . _ : -)"))
}

pub(super) async fn trust(
    client: &mut platform_store::Client,
    command: &TrustCommand,
) -> (Result<String, String>, Option<String>) {
    match command {
        TrustCommand::Add {
            feed_id,
            key_id,
            public_key,
        } => {
            // The trust anchor changes: the audit row names the key's fingerprint.
            let target = Some(match feedfmt::parse_public_key(public_key) {
                Some(key) => format!("{feed_id}/{key_id} {}", feedfmt::fingerprint(&key)),
                None => format!("{feed_id}/{key_id}"),
            });
            let result = async {
                identifier(feed_id, "feed id")?;
                identifier(key_id, "key id")?;
                let key = feedfmt::parse_public_key(public_key)
                    .ok_or("invalid public key (32-byte Ed25519, base64url)")?;
                let fingerprint = feedfmt::fingerprint(&key);
                match feeds::add_trust_key(client, feed_id, key_id, key, Utc::now())
                    .await
                    .map_err(store)?
                {
                    TrustAdded::Added => Ok(format!(
                        "trusted {feed_id}/{key_id}\nfingerprint {fingerprint}\n"
                    )),
                    TrustAdded::AlreadyTrusted => {
                        Ok(format!("already trusted\nfingerprint {fingerprint}\n"))
                    }
                    TrustAdded::Conflict => Err(
                        "key id already used for a different or removed key; use a new key id"
                            .to_owned(),
                    ),
                }
            }
            .await;
            (result, target)
        }
        TrustCommand::List => {
            let result = feeds::trust_keys(client, None)
                .await
                .map_err(store)
                .map(|keys| {
                    if keys.is_empty() {
                        return "no trusted feed keys\n".to_owned();
                    }
                    keys.iter()
                        .map(|key| {
                            let state = key.removed_at.map_or_else(
                                || "trusted".to_owned(),
                                |at| format!("removed {}", time(at)),
                            );
                            format!(
                                "{}/{} {} {state}\n",
                                key.feed_id,
                                key.key_id,
                                feedfmt::fingerprint(&key.public_key)
                            )
                        })
                        .collect()
                });
            (result, None)
        }
        TrustCommand::Remove { feed_id, key_id } => {
            let target = Some(format!("{feed_id}/{key_id}"));
            let result = feeds::remove_trust_key(client, feed_id, key_id, Utc::now())
                .await
                .map_err(store)
                .and_then(|removed| {
                    if removed {
                        Ok("removed\n".to_owned())
                    } else {
                        Err("no such trusted key".to_owned())
                    }
                });
            (result, target)
        }
    }
}

pub(super) async fn applied(client: &platform_store::Client) -> Result<String, String> {
    let states = feeds::feed_states(client).await.map_err(store)?;
    let files = feeds::applied_files(client).await.map_err(store)?;
    if states.is_empty() && files.is_empty() {
        return Ok("no signed feed applied yet\n".into());
    }
    let mut out = String::new();
    for state in &states {
        out.push_str(&format!(
            "{}/{} sequence {} from {} made {} expires {} applied {}\n",
            state.feed_id,
            state.key_id,
            state.sequence,
            state.origin,
            time(state.created_at),
            time(state.expires_at),
            time(state.applied_at)
        ));
    }
    for file in &files {
        out.push_str(&format!(
            "  {} {} fetched {}\n",
            file.source,
            file.kind,
            time(file.fetched_at)
        ));
    }
    Ok(out)
}

/// A work directory only this user can enter, removed when dropped.
struct Work(PathBuf);

impl Work {
    fn new(parent: Option<&Path>) -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let base = parent.map_or_else(std::env::temp_dir, Path::to_path_buf);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = base.join(format!("openvibes-feed-{}-{nonce}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        Ok(Self(dir))
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn line(report: &FileReport) -> String {
    let (word, detail) = match &report.outcome {
        Outcome::Applied(detail) => ("applied", detail.as_str()),
        Outcome::Unchanged => ("unchanged", "already applied"),
        Outcome::Refused(why) => ("REFUSED", why.as_str()),
        Outcome::Skipped(why) => ("skipped", why.as_str()),
    };
    format!(
        "  {} {} {word}: {detail}\n",
        report.source,
        report.kind.as_str()
    )
}

pub(super) async fn import_bundle(
    client: &mut platform_store::Client,
    path: &Path,
    sources: &[String],
    work_dir: Option<&Path>,
) -> (Result<String, String>, Option<String>) {
    let name = path
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let trusted: Vec<TrustedKey> = match feeds::active_trust_keys(client).await {
        Ok(keys) => keys
            .into_iter()
            .map(|(feed_id, key_id, public_key)| TrustedKey {
                feed_id,
                key_id,
                public_key,
            })
            .collect(),
        Err(error) => return (Err(store(error)), None),
    };
    let known: Vec<Applied> = match feeds::feed_states(client).await {
        Ok(states) => states
            .into_iter()
            .map(|state| Applied {
                feed_id: state.feed_id,
                key_id: state.key_id,
                sequence: state.sequence,
                manifest_digest: state.manifest_digest,
            })
            .collect(),
        Err(error) => return (Err(store(error)), None),
    };
    let now = Utc::now();
    // `feed.json` is verified before any blob is copied; only the blobs its
    // manifest names are taken, into a private directory.
    let accepted = std::cell::RefCell::new(None);
    let refusal = std::cell::Cell::new(None);
    let verify = |bytes: &[u8]| -> Result<bundle::Allowed, String> {
        match feedfmt::verify(bytes, &trusted, &known, now.timestamp()) {
            Ok(ok) => {
                let allowed = ok
                    .manifest
                    .files
                    .iter()
                    .map(|file| (file.sha256.clone(), file.size))
                    .collect();
                *accepted.borrow_mut() = Some(ok);
                Ok(allowed)
            }
            Err(why) => {
                refusal.set(Some(why));
                Err(format!("feed refused: {} ({why})", why.as_str()))
            }
        }
    };
    let work = match Work::new(work_dir) {
        Ok(work) => work,
        Err(_) => return (Err("cannot make a work directory".into()), None),
    };
    let unpacked = if path.is_dir() {
        bundle::open_dir(path, &work.0, verify)
    } else {
        bundle::unpack_tar(path, &work.0, verify)
    };
    let unpacked = match unpacked {
        Ok(unpacked) => unpacked,
        Err(error) => {
            let target = refusal
                .get()
                .map(|why| format!("{name} refused: {}", why.as_str()));
            return (Err(error.to_string()), target);
        }
    };
    let Some(accepted) = accepted.into_inner() else {
        return (Err("feed refused".into()), None);
    };
    let label = format!(
        "{}/{} #{}",
        accepted.feed_id, accepted.key_id, accepted.manifest.sequence
    );
    let reports =
        match feedimport::apply(client, &unpacked, &accepted, "bundle", sources, now).await {
            Ok(reports) => reports,
            Err(error) => {
                let target = Some(format!("{label} refused: {error}"));
                return (Err(error), target);
            }
        };
    let count =
        |wanted: fn(&Outcome) -> bool| reports.iter().filter(|r| wanted(&r.outcome)).count();
    let applied = count(|o| matches!(o, Outcome::Applied(_) | Outcome::Unchanged));
    let refused = count(|o| matches!(o, Outcome::Refused(_)));
    let target = Some(format!("{label} applied {applied} refused {refused}"));
    let mut out = format!(
        "feed {} sequence {} signed by {}, made {}\n",
        accepted.feed_id,
        accepted.manifest.sequence,
        accepted.key_id,
        time(DateTime::from_timestamp(accepted.manifest.created_at, 0).unwrap_or_default())
    );
    out.extend(reports.iter().map(line));
    if refused > 0 {
        out.push_str(&format!("{refused} file(s) refused\n"));
        return (Err(out), target);
    }
    (Ok(out), target)
}
