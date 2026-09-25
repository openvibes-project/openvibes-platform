#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! `openvibes-llm-check`: run by `openvibes-llm.service` before it starts
//! `llama-server` (assistant spec §6, plan AS5). It refuses to start the
//! model server unless its settings are in range and the model file is the
//! one the operator installed: a regular file in the models directory,
//! matching the configured SHA-256, and not writable by the service.
//!
//! Settings come from the environment: systemd passes `/etc/openvibes/llm.conf`
//! (the operator's, root-owned) and `/var/lib/openvibes-llm/model.conf` (the
//! model selection `openvibes-admin assistant model install` writes) to both
//! the check and `llama-server` (`EnvironmentFile=`), so the two can never
//! disagree.

use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

use sha2::{Digest, Sha256};

/// Where models are installed.
pub const MODELS_DIR: &str = "/var/lib/openvibes-llm/models";
/// Largest model file accepted.
pub const MAX_MODEL_BYTES: u64 = 256 << 30;

/// A check that failed. Messages name the setting, never secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckError {
    /// A setting is missing.
    Missing(&'static str),
    /// A setting is malformed or out of range.
    Invalid(&'static str),
    /// The model is not a regular `.gguf` file inside the models directory.
    ModelPath,
    /// The model file cannot be read.
    ModelUnreadable,
    /// The model file's SHA-256 differs from the configured one.
    ModelDigest,
    /// The service could modify the model file.
    ModelWritable,
    /// A variable `llama-server` or its libraries read is set (such as
    /// `LLAMA_ARG_TOOLS`); every option must come from the unit.
    ForeignVariable(String),
    /// Running as root: the service must run as its own user.
    Root,
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(
                f,
                "{name} is not set (install a model with openvibes-admin assistant model install)"
            ),
            Self::Invalid(name) => write!(f, "{name} is invalid or out of range"),
            Self::ModelPath => write!(
                f,
                "OPENVIBES_LLM_MODEL must be a regular .gguf file directly inside the models directory"
            ),
            Self::ModelUnreadable => f.write_str("the model file cannot be read"),
            Self::ModelDigest => f.write_str(
                "the model file does not match OPENVIBES_LLM_MODEL_SHA256; reinstall it with openvibes-admin assistant model install",
            ),
            Self::ModelWritable => {
                f.write_str("the model file is writable by the service; it must be read-only")
            }
            Self::ForeignVariable(name) => write!(
                f,
                "{name} is set; llama-server options come only from the unit and OPENVIBES_LLM_* settings"
            ),
            Self::Root => f.write_str("openvibes-llm must not run as root"),
        }
    }
}

impl std::error::Error for CheckError {}

/// Checked settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The model file.
    pub model: PathBuf,
    /// Its expected SHA-256 (lowercase hex).
    pub model_sha256: String,
    /// Name the server reports for the model.
    pub alias: String,
    /// Loopback port.
    pub port: u16,
    /// Context size in tokens.
    pub context: u32,
    /// CPU threads.
    pub threads: u32,
    /// Layers offloaded to a GPU (0 on the CPU build).
    pub gpu_layers: u32,
    /// Requests served at once.
    pub parallel: u32,
}

fn number<T: std::str::FromStr + PartialOrd>(
    env: &BTreeMap<String, String>,
    name: &'static str,
    range: std::ops::RangeInclusive<T>,
) -> Result<T, CheckError> {
    let value = env.get(name).ok_or(CheckError::Missing(name))?;
    value
        .trim()
        .parse::<T>()
        .ok()
        .filter(|n| range.contains(n))
        .ok_or(CheckError::Invalid(name))
}

/// Whether `text` is a SHA-256 in lowercase hex.
#[must_use]
pub fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `name` is a safe model file name: `[A-Za-z0-9._-]`, ending
/// `.gguf`, not starting with a dot.
#[must_use]
pub fn is_model_name(name: &str) -> bool {
    name.len() <= 200
        && name.ends_with(".gguf")
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Variable prefixes `llama-server`, ggml, and the Hugging Face client read
/// from the environment. Any of them could switch on something the unit
/// leaves off (`LLAMA_ARG_TOOLS`, `LLAMA_ARG_MCP_SERVERS_JSON`,
/// `LLAMA_ARG_HOST`, `LLAMA_ARG_MODEL_URL`), and `EnvironmentFile=` hands the
/// check and the server the same variables.
const FOREIGN_PREFIXES: [&str; 4] = ["LLAMA_", "GGML_", "HF_", "HUGGING"];
/// Set by the unit: no crash backtrace (it would start `gdb`).
const ALLOWED_FOREIGN: [&str; 1] = ["GGML_NO_BACKTRACE"];

/// Refuses any variable that would configure `llama-server` behind the
/// unit's back.
pub fn check_environment<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<(), CheckError> {
    for name in names {
        let upper = name.to_ascii_uppercase();
        if FOREIGN_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
            && !ALLOWED_FOREIGN.contains(&name)
        {
            return Err(CheckError::ForeignVariable(name.to_owned()));
        }
    }
    Ok(())
}

/// Reads the settings from `env` (the `OPENVIBES_LLM_*` variables).
pub fn settings(env: &BTreeMap<String, String>, models_dir: &Path) -> Result<Settings, CheckError> {
    let model = env
        .get("OPENVIBES_LLM_MODEL")
        .filter(|v| !v.trim().is_empty())
        .ok_or(CheckError::Missing("OPENVIBES_LLM_MODEL"))?;
    let model = PathBuf::from(model.trim());
    let direct_child = model.parent() == Some(models_dir)
        && model
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && model
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(is_model_name);
    if !direct_child {
        return Err(CheckError::ModelPath);
    }
    let digest = env
        .get("OPENVIBES_LLM_MODEL_SHA256")
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .ok_or(CheckError::Missing("OPENVIBES_LLM_MODEL_SHA256"))?;
    if !is_sha256_hex(&digest) {
        return Err(CheckError::Invalid("OPENVIBES_LLM_MODEL_SHA256"));
    }
    let alias = env
        .get("OPENVIBES_LLM_ALIAS")
        .map(|v| v.trim().to_owned())
        .ok_or(CheckError::Missing("OPENVIBES_LLM_ALIAS"))?;
    let alias_ok = !alias.is_empty()
        && alias.len() <= 64
        && alias
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !alias_ok {
        return Err(CheckError::Invalid("OPENVIBES_LLM_ALIAS"));
    }
    Ok(Settings {
        model,
        model_sha256: digest,
        alias,
        port: number(env, "OPENVIBES_LLM_PORT", 1024..=65535)?,
        context: number(env, "OPENVIBES_LLM_CONTEXT", 512..=131_072)?,
        threads: number(env, "OPENVIBES_LLM_THREADS", 1..=256)?,
        gpu_layers: number(env, "OPENVIBES_LLM_GPU_LAYERS", 0..=999)?,
        parallel: number(env, "OPENVIBES_LLM_PARALLEL", 1..=16)?,
    })
}

/// The SHA-256 of everything `reader` yields, in lowercase hex, reading at
/// most `limit` bytes (more is an error).
pub fn sha256_hex(mut reader: impl Read, limit: u64) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1 << 20];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > limit {
            return Err(io::Error::other("file too large"));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Checks the model file: a regular file (not a link), readable, not
/// writable by this process, and matching the configured SHA-256. Returns
/// its size.
pub fn check_model(settings: &Settings) -> Result<u64, CheckError> {
    let metadata =
        std::fs::symlink_metadata(&settings.model).map_err(|_| CheckError::ModelUnreadable)?;
    if !metadata.file_type().is_file() {
        return Err(CheckError::ModelPath);
    }
    // Opening for writing must fail: by ownership and mode, or because the
    // unit makes the file system read-only. Nothing is written or truncated.
    if OpenOptions::new().write(true).open(&settings.model).is_ok() {
        return Err(CheckError::ModelWritable);
    }
    let file = File::open(&settings.model).map_err(|_| CheckError::ModelUnreadable)?;
    let digest = sha256_hex(file, MAX_MODEL_BYTES).map_err(|_| CheckError::ModelUnreadable)?;
    if digest != settings.model_sha256 {
        return Err(CheckError::ModelDigest);
    }
    Ok(metadata.len())
}

/// Whether this process runs as root (uid 0), read from `/proc/self`.
#[must_use]
pub fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0)
    }
    #[cfg(not(unix))]
    false
}
