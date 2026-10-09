//! `openvibes-admin assistant model fetch`: downloads the model named by
//! `model.pin` from its publisher with curl (HTTPS only) and installs it
//! through the verified `model install` path. Setup and assistant-setup call
//! it; nothing is installed unless the bytes match the pinned SHA-256.
//!
//! The models directory is group-writable and fetch may run as root, so the
//! download goes into a fresh 0700 directory inside it (nobody else can swap
//! the file), is verified and chmod-ed through one open descriptor, and is
//! renamed onto the pinned name. Group members can already replace models,
//! and they could swap that directory for a symlink, so fetch runs only as
//! the openvibes-admin user: `model::run` refuses root (the dirs are
//! group-writable). Callers use `runuser -u openvibes-admin`.
// ponytail: follow-up: models dir group-writable vs root installs (make it
// root-owned, or install as openvibes-admin only).

// curl and stat run with fixed argument lists, no shell.
#[allow(clippy::disallowed_types)]
use std::process::Command;
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use openvibes_llm::{is_model_name, is_sha256_hex};

/// Space the 4B model needs, with headroom for the temporary copy's peak.
const NEEDED_BYTES: u64 = 2_700_000_000;
const CURL: &str = "/usr/bin/curl";
const STAT: &str = "/usr/bin/stat";

/// The values of `model.pin` (the only source of the model's identity).
#[derive(Debug)]
pub struct Pin {
    pub file: String,
    pub url: String,
    pub sha256: String,
    pub alias: String,
    /// Shown by Setup's consent step (Task 3).
    #[allow(dead_code)]
    pub license_url: String,
}

/// Reads `KEY=value` lines; unknown keys and comments are ignored.
pub fn read_pin(path: &Path) -> Result<Pin, String> {
    let text = fs::read_to_string(path).map_err(|_| format!("cannot read {}", path.display()))?;
    parse_pin(&text).map_err(|error| format!("{}: {error}", path.display()))
}

fn parse_pin(text: &str) -> Result<Pin, String> {
    let get = |key: &str| {
        text.lines()
            .filter_map(|line| line.split_once('='))
            .find(|(name, _)| name.trim() == key)
            .map(|(_, value)| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{key} is missing"))
    };
    let pin = Pin {
        file: get("LLM_MODEL_FILE")?,
        url: get("LLM_MODEL_URL")?,
        sha256: get("LLM_MODEL_SHA256")?.to_ascii_lowercase(),
        alias: get("LLM_MODEL_ALIAS")?,
        license_url: get("LLM_MODEL_LICENSE_URL")?,
    };
    if !is_model_name(&pin.file) {
        return Err("LLM_MODEL_FILE is not a plain .gguf file name".into());
    }
    if !is_sha256_hex(&pin.sha256) {
        return Err("LLM_MODEL_SHA256 is not 64 hexadecimal characters".into());
    }
    if !pin.url.starts_with("https://") {
        return Err("LLM_MODEL_URL must be an https:// URL".into());
    }
    Ok(pin)
}

/// The download step, injectable for tests.
pub trait Downloader {
    fn download(&self, url: &str, dest: &Path) -> Result<(), String>;
}

/// curl, HTTPS and TLS 1.2 or newer only; progress goes to the terminal.
pub struct Curl;

impl Downloader for Curl {
    #[allow(clippy::disallowed_types)]
    fn download(&self, url: &str, dest: &Path) -> Result<(), String> {
        let status = Command::new(CURL)
            .args(curl_args(url, dest))
            .status()
            .map_err(|_| "curl is not installed".to_owned())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("curl failed ({status})"))
        }
    }
}

/// `-q` first: no `.curlrc` may change the transfer.
fn curl_args(url: &str, dest: &Path) -> Vec<std::ffi::OsString> {
    let mut args: Vec<std::ffi::OsString> = [
        "-q",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "--fail",
        "--location",
        "--retry",
        "3",
        "--max-filesize",
    ]
    .map(Into::into)
    .to_vec();
    args.push(NEEDED_BYTES.to_string().into());
    args.push("--output".into());
    args.push(dest.into());
    args.push(url.into());
    args
}

/// Bytes available to unprivileged writers on the filesystem holding `dir`
/// (0 if unknown, which refuses the download). `stat` because the crate
/// forbids the unsafe `statvfs` call.
#[allow(clippy::disallowed_types)]
pub fn free_bytes(dir: &Path) -> u64 {
    Command::new(STAT)
        .args(["-f", "-c", "%a %S"])
        .arg(dir)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let text = String::from_utf8(output.stdout).ok()?;
            let mut parts = text.split_whitespace().map(|n| n.parse::<u64>().ok());
            Some(parts.next()??.saturating_mul(parts.next()??))
        })
        .unwrap_or(0)
}

/// Removes the private download directory on drop (`remove_dir_all` does not
/// follow symlinks): every return and panic leaves no download.
struct Private(PathBuf);

impl Drop for Private {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Opens a file for reading without following a symlink at the final name.
fn open_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

/// Removes `.fetch-*` directories left by killed runs.
fn sweep(models_dir: &Path) {
    let Ok(entries) = fs::read_dir(models_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let leftover = entry.file_name().to_string_lossy().starts_with(".fetch-");
        if leftover && fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
            let _ = fs::remove_dir_all(&path);
        }
    }
}

/// Downloads and installs the pinned model unless it is already installed
/// and selected. Only verified bytes ever reach the pinned name: the
/// download is hashed in place and renamed over it (no second copy).
pub fn fetch(
    pin: &Pin,
    downloader: &dyn Downloader,
    models_dir: &Path,
    model_config: &Path,
    free_bytes: impl Fn(&Path) -> u64,
) -> Result<String, String> {
    if !models_dir.is_dir() {
        return Err(format!(
            "{} does not exist; is openvibes-llm installed?",
            models_dir.display()
        ));
    }
    let config = crate::model::read_config(model_config)?;
    let destination = models_dir.join(&pin.file);
    let has = |line: String| config.lines().any(|l| l.trim() == line);
    let selected = has(format!("OPENVIBES_LLM_MODEL={}", destination.display()))
        && has(format!("OPENVIBES_LLM_MODEL_SHA256={}", pin.sha256));
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.is_file() => {
            // ponytail: "selected" is read from model.conf, not re-hashed.
            if selected {
                return Ok(format!(
                    "already installed: {} (pinned sha256 {}); nothing downloaded\n",
                    pin.file, pin.sha256
                ));
            }
            let matches = open_nofollow(&destination)
                .map_err(|_| "cannot read the installed model".to_owned())
                .and_then(|file| {
                    if file.metadata().is_ok_and(|m| m.is_file()) {
                        crate::model::digest(file)
                    } else {
                        Err("not a regular file".to_owned())
                    }
                })
                .is_ok_and(|digest| digest == pin.sha256);
            if matches {
                return crate::model::select(
                    &config,
                    &destination,
                    metadata.len(),
                    &pin.sha256,
                    Some(&pin.alias),
                    model_config,
                );
            }
            // Corrupt or foreign: replaced below by the verified download.
        }
        Ok(_) => {
            return Err(format!(
                "{} exists and is not a file",
                destination.display()
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("cannot inspect the models directory".into()),
    }
    let free = free_bytes(models_dir);
    if free < NEEDED_BYTES {
        return Err(format!(
            "need about 2.7 GB free in {}, have {:.1} GB",
            models_dir.display(),
            free as f64 / 1e9
        ));
    }
    sweep(models_dir);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let private = models_dir.join(format!(".fetch-{}-{nanos}", std::process::id()));
    // Never reuses a directory: create fails if the name exists.
    DirBuilder::new()
        .mode(0o700)
        .create(&private)
        .map_err(|_| "cannot create a private download directory".to_owned())?;
    let private = Private(private);
    let temporary = private.0.join(&pin.file);
    downloader.download(&pin.url, &temporary).map_err(|error| {
        format!(
            "cannot download {}: {error}\noffline: download it elsewhere, then `openvibes-admin assistant model install FILE --sha256 {}`",
            pin.url, pin.sha256
        )
    })?;
    // One descriptor for sync, size, hash and chmod; the directory is ours.
    let file = open_nofollow(&temporary).map_err(|_| "cannot read the download".to_owned())?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot read the download".to_owned())?;
    if !metadata.is_file() {
        return Err("the download is not a regular file".into());
    }
    let size = metadata.len();
    // Flushed before the rename: a power loss must not leave a truncated file
    // at the pinned name, which "selected" trusts without a re-hash.
    file.sync_all()
        .map_err(|_| "cannot write the model (disk full?)".to_owned())?;
    let digest = crate::model::digest(&file)?;
    if digest != pin.sha256 {
        return Err(format!(
            "the downloaded file does not match the pinned SHA-256 ({}); nothing was installed",
            pin.url
        ));
    }
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o444))
        .map_err(|_| "cannot set file permissions".to_owned())?;
    fs::rename(&temporary, &destination).map_err(|_| "cannot install the model".to_owned())?;
    crate::model::select(
        &config,
        &destination,
        size,
        &pin.sha256,
        Some(&pin.alias),
        model_config,
    )
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use sha2::{Digest, Sha256};

    use super::*;

    const BYTES: &[u8] = b"fake model bytes";

    struct Fake {
        bytes: &'static [u8],
        calls: Cell<u32>,
    }

    impl Downloader for Fake {
        fn download(&self, _: &str, dest: &Path) -> Result<(), String> {
            self.calls.set(self.calls.get() + 1);
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dest.parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "download dir is private");
            fs::write(dest, self.bytes).map_err(|e| e.to_string())
        }
    }

    fn fake(bytes: &'static [u8]) -> Fake {
        Fake {
            bytes,
            calls: Cell::new(0),
        }
    }

    fn pin() -> Pin {
        let sha256 = Sha256::digest(BYTES)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Pin {
            file: "m.gguf".into(),
            url: "https://example.test/m.gguf".into(),
            sha256,
            alias: "m".into(),
            license_url: "https://example.test/LICENSE".into(),
        }
    }

    fn dirs(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("ov-fetch-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let models = root.join("models");
        fs::create_dir_all(&models).unwrap();
        (models, root.join("model.conf"))
    }

    fn names(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn real_pin_parses() {
        let pin = parse_pin(include_str!("../../../packaging/llm/model.pin")).unwrap();
        assert!(pin.file.ends_with(".gguf") && pin.url.starts_with("https://"));
        assert!(!pin.alias.is_empty() && !pin.license_url.is_empty());
    }

    #[test]
    fn missing_key_is_named() {
        let error = parse_pin("LLM_MODEL_FILE=a.gguf\n").unwrap_err();
        assert!(error.contains("LLM_MODEL_URL is missing"), "{error}");
    }

    #[test]
    fn good_download_installs_and_selects() {
        let (models, config) = dirs("good");
        let downloader = fake(BYTES);
        let pin = pin();
        fetch(&pin, &downloader, &models, &config, |_| u64::MAX).unwrap();
        assert_eq!(fs::read(models.join("m.gguf")).unwrap(), BYTES);
        assert_eq!(names(&models), ["m.gguf"]);
        let conf = fs::read_to_string(&config).unwrap();
        assert!(conf.contains(&format!("OPENVIBES_LLM_MODEL_SHA256={}", pin.sha256)));
        assert!(conf.contains("OPENVIBES_LLM_ALIAS=m"));
        // A second run downloads nothing.
        let message = fetch(&pin, &downloader, &models, &config, |_| u64::MAX).unwrap();
        assert!(
            message.starts_with("already installed: m.gguf"),
            "{message}"
        );
        assert_eq!(downloader.calls.get(), 1);
    }

    #[test]
    fn present_but_unselected_is_selected_without_download() {
        let (models, config) = dirs("unsel");
        fs::write(models.join("m.gguf"), BYTES).unwrap();
        let downloader = fake(BYTES);
        let pin = pin();
        let message = fetch(&pin, &downloader, &models, &config, |_| 0).unwrap();
        assert!(message.starts_with("installed "), "{message}");
        assert_eq!(downloader.calls.get(), 0);
        let conf = fs::read_to_string(&config).unwrap();
        assert!(conf.contains(&format!("OPENVIBES_LLM_MODEL_SHA256={}", pin.sha256)));
    }

    #[test]
    fn planted_symlink_and_old_leftovers_are_harmless() {
        let (models, config) = dirs("plant");
        let victim = models.parent().unwrap().join("victim");
        fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, models.join(".m.gguf.download")).unwrap();
        let old = models.join(".fetch-1-1");
        fs::create_dir(&old).unwrap();
        fs::write(old.join("m.gguf"), b"stale").unwrap();
        fetch(&pin(), &fake(BYTES), &models, &config, |_| u64::MAX).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert!(!old.exists());
        assert!(names(&models).iter().all(|n| !n.starts_with(".fetch-")));
    }

    #[test]
    fn curl_runs_without_rc_files_and_by_absolute_path() {
        let args = curl_args("https://x.test/m", Path::new("/d/m"));
        assert_eq!(args[0], "-q");
        assert!(args.iter().any(|a| a == "--max-filesize"));
        assert!(CURL.starts_with("/usr/bin/") && STAT.starts_with("/usr/bin/"));
    }

    #[test]
    fn http_url_is_rejected() {
        let text = include_str!("../../../packaging/llm/model.pin")
            .replace("LLM_MODEL_URL=https://", "LLM_MODEL_URL=http://");
        assert!(parse_pin(&text).unwrap_err().contains("https://"));
    }

    #[test]
    fn missing_models_dir_is_refused() {
        let (models, config) = dirs("nodir");
        let gone = models.join("absent");
        let downloader = fake(BYTES);
        let error = fetch(&pin(), &downloader, &gone, &config, |_| u64::MAX).unwrap_err();
        assert!(error.contains("does not exist"), "{error}");
        assert_eq!(downloader.calls.get(), 0);
    }

    #[test]
    fn wrong_contents_under_the_pinned_name_are_replaced() {
        let (models, config) = dirs("foreign");
        fs::write(models.join("m.gguf"), b"foreign").unwrap();
        let downloader = fake(BYTES);
        fetch(&pin(), &downloader, &models, &config, |_| u64::MAX).unwrap();
        assert_eq!(fs::read(models.join("m.gguf")).unwrap(), BYTES);
        assert_eq!(downloader.calls.get(), 1);
        assert_eq!(names(&models), ["m.gguf"]);
    }

    #[test]
    fn failure_after_download_leaves_no_temp_file_and_a_rerun_selects() {
        let (models, config) = dirs("late");
        // read_config tolerates a missing file; writing it then fails.
        let unwritable = models.join("no-such-dir").join("model.conf");
        let downloader = fake(BYTES);
        let pin = pin();
        assert!(fetch(&pin, &downloader, &models, &unwritable, |_| u64::MAX).is_err());
        // The verified model stays in place; only the temp file is gone.
        assert_eq!(names(&models), ["m.gguf"]);
        let message = fetch(&pin, &downloader, &models, &config, |_| 0).unwrap();
        assert!(message.starts_with("installed "), "{message}");
        assert_eq!(downloader.calls.get(), 1);
    }

    #[test]
    fn mismatch_installs_nothing() {
        let (models, config) = dirs("bad");
        let error = fetch(&pin(), &fake(b"other"), &models, &config, |_| u64::MAX).unwrap_err();
        assert!(
            error.contains("does not match the pinned SHA-256"),
            "{error}"
        );
        assert!(names(&models).is_empty());
        assert!(!config.exists());
    }

    #[test]
    fn low_disk_is_refused_before_download() {
        let (models, config) = dirs("disk");
        let downloader = fake(BYTES);
        let error = fetch(&pin(), &downloader, &models, &config, |_| 1000).unwrap_err();
        assert!(error.contains("need about 2.7 GB free"), "{error}");
        assert_eq!(downloader.calls.get(), 0);
    }

    #[test]
    fn download_error_names_url_and_offline_route() {
        struct Down;
        impl Downloader for Down {
            fn download(&self, _: &str, dest: &Path) -> Result<(), String> {
                fs::write(dest, b"partial").unwrap();
                Err("curl failed".into())
            }
        }
        let (models, config) = dirs("down");
        let error = fetch(&pin(), &Down, &models, &config, |_| u64::MAX).unwrap_err();
        assert!(error.contains("https://example.test/m.gguf"), "{error}");
        assert!(error.contains("model install FILE --sha256"), "{error}");
        assert!(names(&models).is_empty());
    }
}
