//! The signer's own state: the last version it signed per set (so it
//! always signs last + 1 and a console can't roll a set back), the last
//! rules it signed, the publish rate, and `status.json` for Health.

use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::request::{Refusal, SITE, SITE_ALARMS};

const VERSIONS: &str = "versions.json";
const STATUS: &str = "status.json";
const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 24 * HOUR_MS;

/// One set's last signature.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetState {
    /// The last version signed (0: none yet; the next is 1).
    pub version: u64,
    /// When that signature expires.
    pub expires_at_unix_ms: Option<i64>,
}

/// What `seed` did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Seeded {
    /// There was no version state.
    Created,
    /// A readable state was kept.
    Kept,
    /// An unreadable state was replaced.
    Replaced,
}

/// In memory: the publish rate and refusals reset on restart, which a
/// console can't cause.
pub struct State {
    dir: PathBuf,
    sets: Option<BTreeMap<String, SetState>>,
    publishes: VecDeque<i64>,
    /// Refusals per code, per hour (the hour's start), for the last day:
    /// bounded however many requests arrive.
    refusals: BTreeMap<i64, BTreeMap<Refusal, u64>>,
    /// `status.json` is behind.
    dirty: bool,
    written_at_ms: i64,
}

impl State {
    /// Reads `versions.json` from `dir`. Missing or invalid means no
    /// version state: every request is refused until Setup seeds it.
    #[must_use]
    pub fn open(dir: &Path) -> Self {
        let sets = fs::read(dir.join(VERSIONS))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<BTreeMap<String, SetState>>(&bytes).ok())
            .filter(|sets| sets.contains_key(SITE) && sets.contains_key(SITE_ALARMS));
        Self {
            dir: dir.to_owned(),
            sets,
            publishes: VecDeque::new(),
            refusals: BTreeMap::new(),
            dirty: true,
            written_at_ms: i64::MIN,
        }
    }

    /// Creates `versions.json` so the next version signed is `min_version`
    /// (at least the version agents last accepted, after a restore). A
    /// readable file is kept: seeding never lowers a version. One that
    /// can't be read (corrupt, or missing a set) is replaced.
    ///
    /// # Errors
    /// `min_version` 0, or the file can't be written.
    pub fn seed(dir: &Path, min_version: u64) -> Result<Seeded, String> {
        if min_version == 0 {
            return Err("--min-version must be at least 1".into());
        }
        let existed = dir.join(VERSIONS).exists();
        if existed && Self::open(dir).sets.is_some() {
            return Ok(Seeded::Kept);
        }
        let last = SetState {
            version: min_version - 1,
            expires_at_unix_ms: None,
        };
        let sets = BTreeMap::from([(SITE.to_owned(), last), (SITE_ALARMS.to_owned(), last)]);
        write_atomic(
            dir,
            VERSIONS,
            0o600,
            &serde_json::to_vec_pretty(&sets).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("cannot write {}: {e}", dir.join(VERSIONS).display()))?;
        Ok(if existed {
            Seeded::Replaced
        } else {
            Seeded::Created
        })
    }

    /// The version to sign `rule_set` with next, if the state is known.
    #[must_use]
    pub fn next_version(&self, rule_set: &str) -> Option<u64> {
        self.sets.as_ref()?.get(rule_set)?.version.checked_add(1)
    }

    /// Successful publishes within the last hour.
    pub fn publishes_this_hour(&mut self, now_ms: i64) -> usize {
        while self
            .publishes
            .front()
            .is_some_and(|at| *at <= now_ms - HOUR_MS)
        {
            self.publishes.pop_front();
        }
        self.publishes.len()
    }

    /// Records a signature: the rules and the new version reach disk before
    /// the envelope is handed out, so a version is never signed twice.
    ///
    /// # Errors
    /// The state can't be written; the envelope must then not be used.
    pub fn record_signed(
        &mut self,
        rule_set: &str,
        version: u64,
        expires_at_unix_ms: i64,
        payload: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        let mut sets = self.sets.clone().ok_or("no version state")?;
        sets.insert(
            rule_set.to_owned(),
            SetState {
                version,
                expires_at_unix_ms: Some(expires_at_unix_ms),
            },
        );
        write_atomic(
            &self.dir,
            &format!("{rule_set}.rules.json"),
            0o600,
            payload.as_bytes(),
        )
        .and_then(|()| {
            let bytes = serde_json::to_vec_pretty(&sets).map_err(std::io::Error::other)?;
            write_atomic(&self.dir, VERSIONS, 0o600, &bytes)
        })
        .map_err(|e| format!("cannot write the signer state: {e}"))?;
        self.sets = Some(sets);
        self.publishes.push_back(now_ms);
        self.dirty = true;
        // A signature reaches status.json now, not at the next tick.
        self.written_at_ms = i64::MIN;
        Ok(())
    }

    /// Counts a refusal for `status.json` (kept for a day).
    pub fn record_refusal(&mut self, code: Refusal, now_ms: i64) {
        *self
            .refusals
            .entry(now_ms - now_ms.rem_euclid(HOUR_MS))
            .or_default()
            .entry(code)
            .or_default() += 1;
        self.dirty = true;
    }

    /// Writes `status.json` (0640; the state directory's group is the
    /// operators'), atomically so Health never reads half a file. At most
    /// once a second unless `flush` (the serve loop's tick), and only when
    /// something changed; a signature is written at once.
    ///
    /// # Errors
    /// The file can't be written.
    pub fn write_status(&mut self, now_ms: i64, flush: bool) -> std::io::Result<()> {
        let due = now_ms.saturating_sub(self.written_at_ms) >= 1_000;
        if !self.dirty || !(flush || due) {
            return Ok(());
        }
        self.refusals
            .retain(|hour, _| *hour > now_ms - DAY_MS - HOUR_MS);
        let mut refusals: BTreeMap<&str, u64> = BTreeMap::new();
        for codes in self.refusals.values() {
            for (code, count) in codes {
                *refusals.entry(code.code()).or_default() += count;
            }
        }
        let status = serde_json::json!({
            "updated_at_unix_ms": now_ms,
            "version_state": self.sets.is_some(),
            "sets": self.sets,
            "publishes_last_hour": self.publishes_this_hour(now_ms),
            "refusals_last_day": refusals,
        });
        let bytes = serde_json::to_vec_pretty(&status).map_err(std::io::Error::other)?;
        write_atomic(&self.dir, STATUS, 0o640, &bytes)?;
        self.dirty = false;
        self.written_at_ms = now_ms;
        Ok(())
    }
}

/// Writes `name` in `dir` through a temporary file, fsync and rename, then
/// fsyncs the directory.
fn write_atomic(dir: &Path, name: &str, mode: u32, bytes: &[u8]) -> std::io::Result<()> {
    let temp = dir.join(format!(".{name}.tmp"));
    let _ = fs::remove_file(&temp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temp, dir.join(name))?;
    File::open(dir)?.sync_all()
}
