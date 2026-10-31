//! One build or bundle at a time per feed tree. The daily timer and an
//! operator running `build` by hand would otherwise race on `feed.json`, the
//! state files and the blobs; the second one stops with a clear message.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::path::Path;

/// The lock file's name, inside the tree. It is not part of the feed.
pub const NAME: &str = ".build.lock";

/// Takes the tree's lock for as long as the returned file lives (the
/// system releases it when the process ends, even if it crashes).
pub fn hold(dir: &Path) -> Result<File, String> {
    fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(NAME))
        .map_err(|e| format!("cannot open {}: {e}", dir.join(NAME).display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(format!(
            "another build or bundle is running in {}; wait for it to finish",
            dir.display()
        )),
        Err(TryLockError::Error(e)) => {
            Err(format!("cannot lock {}: {e}", dir.join(NAME).display()))
        }
    }
}
