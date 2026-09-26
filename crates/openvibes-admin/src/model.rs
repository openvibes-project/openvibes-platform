//! `openvibes-admin assistant model install`: verifies a GGUF model file
//! against the SHA-256 the operator got from its publisher, installs it
//! read-only for `openvibes-llm`, and selects it in
//! `/var/lib/openvibes-llm/model.conf` (assistant spec §6, §9). The platform
//! never downloads models itself. Runs as `openvibes_admin`, whose group owns
//! `/var/lib/openvibes-llm`; the service's own settings stay root's in
//! `/etc/openvibes/llm.conf`.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use clap::Subcommand;
use openvibes_llm::{MAX_MODEL_BYTES, MODELS_DIR, is_model_name, is_sha256_hex};
use sha2::{Digest, Sha256};

/// The model selection `openvibes-llm.service` reads after `llm.conf`.
const MODEL_CONFIG: &str = "/var/lib/openvibes-llm/model.conf";
/// Largest `model.conf` read.
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Subcommand)]
pub enum ModelCommand {
    /// Verify a GGUF file against its published SHA-256, install it
    /// read-only, and select it for openvibes-llm; then restart it.
    Install {
        /// The downloaded model file.
        file: PathBuf,
        /// The SHA-256 its publisher lists (64 hexadecimal characters).
        #[arg(long)]
        sha256: String,
        /// File name to install as (default: the file's own name).
        #[arg(long)]
        name: Option<String>,
        /// Model name the server reports; must match `model` in the
        /// console's `[assistant.backend]`.
        #[arg(long)]
        alias: Option<String>,
        /// Models directory.
        #[arg(long, default_value = MODELS_DIR)]
        models_dir: PathBuf,
        /// The model selection file.
        #[arg(long, default_value = MODEL_CONFIG)]
        model_config: PathBuf,
    },
}

/// Runs a model command; the audit target is the installed file name.
pub fn run(command: &ModelCommand) -> (Result<String, String>, Option<String>) {
    let ModelCommand::Install {
        file,
        sha256,
        name,
        alias,
        models_dir,
        model_config,
    } = command;
    let name = name.clone().or_else(|| {
        file.file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
    });
    let Some(name) = name.filter(|name| is_model_name(name)) else {
        return (
            Err("the model file name must end in .gguf and use only letters, digits, '.', '_', and '-' (see --name)".into()),
            None,
        );
    };
    let target = Some(name.clone());
    let result = install(
        file,
        sha256,
        &name,
        alias.as_deref(),
        models_dir,
        model_config,
    );
    (result, target)
}

fn install(
    source: &Path,
    sha256: &str,
    name: &str,
    alias: Option<&str>,
    models_dir: &Path,
    model_config: &Path,
) -> Result<String, String> {
    let expected = sha256.trim().to_ascii_lowercase();
    if !is_sha256_hex(&expected) {
        return Err("--sha256 must be 64 hexadecimal characters".into());
    }
    if let Some(alias) = alias {
        let valid = !alias.is_empty()
            && alias.len() <= 64
            && alias
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !valid {
            return Err("--alias must be 1-64 letters, digits, '.', '_', or '-'".into());
        }
    }
    match fs::symlink_metadata(models_dir) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(format!("{} is not a directory", models_dir.display())),
        Err(_) => {
            return Err(format!(
                "{} does not exist; is openvibes-llm installed?",
                models_dir.display()
            ));
        }
    }
    // The settings file is read before anything is copied, so a bad one
    // fails the command without leaving a model behind.
    let config = read_config(model_config)?;
    let destination = models_dir.join(name);
    let size = match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.is_file() => {
            let digest = File::open(&destination)
                .map_err(|_| "cannot read the installed model".to_owned())
                .and_then(digest)?;
            if digest != expected {
                return Err(format!(
                    "{} is already installed with different contents; choose another --name",
                    destination.display()
                ));
            }
            metadata.len()
        }
        Ok(_) => {
            return Err(format!(
                "{} exists and is not a file",
                destination.display()
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            copy_verified(source, models_dir, name, &expected)?
        }
        Err(_) => return Err("cannot inspect the models directory".into()),
    };
    let updated = update_config(&config, &destination, &expected, alias);
    write_replacing(model_config, &updated, 0o644)?;
    Ok(format!(
        "installed {} ({} MiB, sha256 {expected})\nupdated {}\nnext: systemctl restart openvibes-llm\n",
        destination.display(),
        size >> 20,
        model_config.display(),
    ))
}

fn digest(mut reader: impl Read) -> Result<String, String> {
    openvibes_llm::sha256_hex(&mut reader, MAX_MODEL_BYTES)
        .map_err(|_| "cannot read the model file, or it exceeds 256 GiB".to_owned())
}

/// Copies `source` into `dir/name` through a temporary file, hashing what it
/// copies: the model is installed only if the copied bytes match.
fn copy_verified(source: &Path, dir: &Path, name: &str, expected: &str) -> Result<u64, String> {
    let metadata = fs::metadata(source).map_err(|_| "model file not found".to_owned())?;
    if !metadata.is_file() {
        return Err("the model must be a regular file".into());
    }
    let mut input = File::open(source).map_err(|_| "cannot read the model file".to_owned())?;
    let temporary = dir.join(format!(".{name}.{}.part", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut output = options
        .open(&temporary)
        .map_err(|_| "cannot write to the models directory".to_owned())?;
    let copied = (|| -> Result<u64, String> {
        let mut hasher = Sha256::new();
        let mut buffer = vec![0; 1 << 20];
        let mut total = 0u64;
        loop {
            let read = input
                .read(&mut buffer)
                .map_err(|_| "cannot read the model file".to_owned())?;
            if read == 0 {
                break;
            }
            total += read as u64;
            if total > MAX_MODEL_BYTES {
                return Err("the model file exceeds 256 GiB".into());
            }
            hasher.update(&buffer[..read]);
            output
                .write_all(&buffer[..read])
                .map_err(|_| "cannot write the model (disk full?)".to_owned())?;
        }
        let actual: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if actual != expected {
            return Err(format!(
                "SHA-256 mismatch: the file is {actual}, expected {expected}; nothing installed"
            ));
        }
        output
            .sync_all()
            .map_err(|_| "cannot write the model (disk full?)".to_owned())?;
        set_mode(&temporary, 0o444)?;
        fs::rename(&temporary, dir.join(name))
            .map_err(|_| "cannot install the model".to_owned())?;
        Ok(total)
    })();
    if copied.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    copied
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| "cannot set file permissions".to_owned())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

fn read_config(path: &Path) -> Result<String, String> {
    let mut text = String::new();
    match File::open(path)
        .and_then(|file| file.take(MAX_CONFIG_BYTES + 1).read_to_string(&mut text))
    {
        Ok(length) if length as u64 <= MAX_CONFIG_BYTES => Ok(text),
        Ok(_) => Err(format!("{} exceeds 64 KiB", path.display())),
        // The first install creates it.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(_) => Err(format!("cannot read {}", path.display())),
    }
}

/// Sets `OPENVIBES_LLM_MODEL`, `OPENVIBES_LLM_MODEL_SHA256`, and (when
/// given) `OPENVIBES_LLM_ALIAS`, keeping every other line and comment.
fn update_config(text: &str, model: &Path, sha256: &str, alias: Option<&str>) -> String {
    let mut wanted = vec![
        ("OPENVIBES_LLM_MODEL", model.display().to_string()),
        ("OPENVIBES_LLM_MODEL_SHA256", sha256.to_owned()),
    ];
    if let Some(alias) = alias {
        wanted.push(("OPENVIBES_LLM_ALIAS", alias.to_owned()));
    }
    let mut seen = vec![false; wanted.len()];
    let mut out = String::new();
    for line in text.lines() {
        let key = line.split_once('=').map(|(key, _)| key.trim());
        match wanted.iter().position(|(name, _)| Some(*name) == key) {
            Some(index) if !seen[index] => {
                seen[index] = true;
                out.push_str(&format!("{}={}\n", wanted[index].0, wanted[index].1));
            }
            // A repeated key would override the new value: drop it.
            Some(_) => {}
            None => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    for (index, (name, value)) in wanted.iter().enumerate() {
        if !seen[index] {
            out.push_str(&format!("{name}={value}\n"));
        }
    }
    out
}

/// Replaces `path` atomically with `contents`.
fn write_replacing(path: &Path, contents: &str, mode: u32) -> Result<(), String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("invalid settings path")?;
    let temporary = path.with_file_name(format!(".{name}.{}.new", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    let written = options
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(contents.as_bytes())?;
            file.sync_all()
        })
        .map_err(|_| format!("cannot write {}", path.display()))
        .and_then(|()| {
            fs::rename(&temporary, path).map_err(|_| format!("cannot replace {}", path.display()))
        });
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_update_keeps_other_lines_and_drops_repeats() {
        let text = "# comment\nOPENVIBES_LLM_PORT=8091\nOPENVIBES_LLM_MODEL=/old.gguf\nOPENVIBES_LLM_MODEL=/older.gguf\n";
        let updated = update_config(text, Path::new("/m/new.gguf"), &"a".repeat(64), Some("x"));
        assert_eq!(
            updated,
            format!(
                "# comment\nOPENVIBES_LLM_PORT=8091\nOPENVIBES_LLM_MODEL=/m/new.gguf\nOPENVIBES_LLM_MODEL_SHA256={}\nOPENVIBES_LLM_ALIAS=x\n",
                "a".repeat(64)
            )
        );
    }
}
