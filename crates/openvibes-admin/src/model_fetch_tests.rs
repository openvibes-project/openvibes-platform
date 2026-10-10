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
    assert!(error.contains("need about 2.8 GB free"), "{error}");
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
    assert!(error.contains("offline install guide"), "{error}");
    assert!(!error.contains('`'), "no command for users: {error}");
    assert!(names(&models).is_empty());
}
