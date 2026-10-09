//! `openvibes-admin assistant model fetch`: downloads the model named by
//! `model.pin` from its publisher with curl (HTTPS only) and installs it
//! through the verified `model install` path. Setup and assistant-setup call
//! it; nothing is installed unless the bytes match the pinned SHA-256.

use std::{fs, path::Path, process::Command};

use openvibes_llm::{is_model_name, is_sha256_hex};

/// Space the 4B model needs, with headroom for the temporary copy's peak.
const NEEDED_BYTES: u64 = 2_700_000_000;

/// The values of `model.pin` (the only source of the model's identity).
pub struct Pin {
    pub file: String,
    pub url: String,
    pub sha256: String,
    pub alias: String,
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
    fn download(&self, url: &str, dest: &Path) -> Result<(), String> {
        let status = Command::new("curl")
            .args(["--proto", "=https", "--tlsv1.2", "--fail", "--location"])
            .args(["--retry", "3", "--output"])
            .arg(dest)
            .arg(url)
            .status()
            .map_err(|_| "curl is not installed".to_owned())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("curl failed ({status})"))
        }
    }
}

/// Bytes available to unprivileged writers on the filesystem holding `dir`
/// (0 if unknown, which refuses the download). `stat` because the crate
/// forbids the unsafe `statvfs` call.
pub fn free_bytes(dir: &Path) -> u64 {
    Command::new("stat")
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

/// Downloads and installs the pinned model unless it is already installed.
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
    // ponytail: presence, not a re-hash of 2.5 GB; the file is 0444 and was
    // verified when installed.
    if models_dir.join(&pin.file).exists() {
        return Ok(format!(
            "already installed: {} (pinned sha256 {}); nothing downloaded\n",
            pin.file, pin.sha256
        ));
    }
    let free = free_bytes(models_dir);
    if free < NEEDED_BYTES {
        return Err(format!(
            "need about 2.7 GB free in {}, have {free} bytes",
            models_dir.display()
        ));
    }
    let temporary = models_dir.join(format!(".{}.download", pin.file));
    let _ = fs::remove_file(&temporary);
    let result = downloader
        .download(&pin.url, &temporary)
        .map_err(|error| {
            format!(
                "cannot download {}: {error}\noffline: download it elsewhere, then `openvibes-admin assistant model install FILE --sha256 {}`",
                pin.url, pin.sha256
            )
        })
        .and_then(|()| {
            crate::model::install(
                &temporary,
                &pin.sha256,
                &pin.file,
                Some(&pin.alias),
                models_dir,
                model_config,
            )
            .map_err(|error| {
                if error.starts_with("SHA-256 mismatch") {
                    format!(
                        "the downloaded file does not match the pinned SHA-256 ({}); nothing was installed",
                        pin.url
                    )
                } else {
                    error
                }
            })
        });
    let _ = fs::remove_file(&temporary);
    result
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
