//! Live progress of the model download for the operator's TUI: while the
//! root helper runs the fetch, a thread writes `<done> <total>` to
//! `/run/openvibes-admin/model-progress` (0644, replaced atomically) from
//! the size of the growing partial file. The file is removed when the
//! guard drops: success, failure and panic alike.

use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

/// Where the progress file lives under the root.
pub const FILE: &str = "run/openvibes-admin/model-progress";

/// The pinned model's size (2.74 GB for Qwen3.5-4B Q4_K_M), known locally so
/// no request is needed for the total.
pub const MODEL_BYTES: u64 = 2_740_000_000;

const EVERY: Duration = Duration::from_millis(500);

/// Bytes of `<models>/.fetch-*/<name>`, the file `model_fetch::fetch` grows.
/// Symlinks are not followed (the models directory is group-writable).
fn done_bytes(models: &Path, name: &str) -> u64 {
    let Ok(entries) = fs::read_dir(models) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(".fetch-"))
        .filter_map(|e| fs::symlink_metadata(e.path().join(name)).ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .max()
        .unwrap_or(0)
}

fn write(file: &Path, done: u64, total: u64) -> std::io::Result<()> {
    let tmp = file.with_extension("tmp");
    let mut out = fs::File::create(&tmp)?;
    out.set_permissions(fs::Permissions::from_mode(0o644))?;
    writeln!(out, "{done} {total}")?;
    fs::rename(&tmp, file)
}

/// Keeps the progress file current until dropped.
pub struct Watch {
    file: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Watch {
    /// Starts writing; `total` 0 means unknown. A directory that cannot be
    /// made just means no progress is shown.
    pub fn start(root: &Path, models: PathBuf, name: String, total: u64) -> Self {
        let file = root.join(FILE);
        let _ = fs::create_dir_all(file.parent().unwrap_or(root));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (file, stop) = (file.clone(), stop.clone());
            thread::spawn(move || {
                while !stop.load(Relaxed) {
                    let _ = write(&file, done_bytes(&models, &name), total);
                    thread::sleep(EVERY);
                }
            })
        };
        Self {
            file,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.stop.store(true, Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join(); // a panic in it is ignored; the file goes anyway
        }
        let _ = fs::remove_file(&self.file);
        let _ = fs::remove_file(self.file.with_extension("tmp"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs(test: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("ov-progress-{}-{test}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let models = root.join("models");
        fs::create_dir_all(models.join(".fetch-1-2")).unwrap();
        (root, models)
    }

    fn read(root: &Path) -> Option<String> {
        fs::read_to_string(root.join(FILE)).ok()
    }

    fn wait_for(root: &Path, want: &str) {
        for _ in 0..100 {
            if read(root).as_deref() == Some(want) {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("wanted {want:?}, have {:?}", read(root));
    }

    #[test]
    fn it_follows_the_growing_file_and_leaves_nothing() {
        let (root, models) = dirs("grow");
        let part = models.join(".fetch-1-2/m.gguf");
        fs::write(&part, vec![0; 10]).unwrap();
        let watch = Watch::start(&root, models, "m.gguf".into(), 100);
        wait_for(&root, "10 100\n");
        let mode = fs::metadata(root.join(FILE)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
        fs::write(&part, vec![0; 60]).unwrap();
        wait_for(&root, "60 100\n");
        drop(watch);
        assert!(read(&root).is_none());
    }

    #[test]
    fn a_failed_download_still_removes_it() {
        let (root, models) = dirs("fail");
        let result = std::panic::catch_unwind(|| {
            let _watch = Watch::start(&root, models, "m.gguf".into(), 0);
            wait_for(&root, "0 0\n");
            panic!("download failed");
        });
        assert!(result.is_err());
        assert!(read(&root).is_none());
    }
}
