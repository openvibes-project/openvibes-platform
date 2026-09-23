#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Bounded, strict TOML configuration loading shared by platform services.

use std::{
    fmt,
    fs::File,
    io::{self, Read},
    path::Path,
};

use serde::de::DeserializeOwned;

/// Largest accepted configuration file.
const MAX_BYTES: u64 = 64 * 1024;

/// Fixed failure categories; no file content or path is ever included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// The file does not exist.
    Missing,
    /// The file exceeds 64 KiB.
    TooLarge,
    /// The file is unreadable, not UTF-8, not TOML, or has unknown or
    /// mistyped keys.
    Invalid,
    /// A configured path is not absolute.
    RelativePath,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "configuration file not found",
            Self::TooLarge => "configuration file exceeds 64 KiB",
            Self::Invalid => "invalid configuration file",
            Self::RelativePath => "configured paths must be absolute",
        })
    }
}

impl std::error::Error for ConfigError {}

/// Reads at most 64 KiB from `path` and parses it as TOML into `T`, which
/// should use `#[serde(deny_unknown_fields)]` so typos fail loudly.
pub fn load<T: DeserializeOwned>(path: &Path) -> Result<T, ConfigError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(ConfigError::Missing),
        Err(_) => return Err(ConfigError::Invalid),
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError::Invalid)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BYTES {
        return Err(ConfigError::TooLarge);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ConfigError::Invalid)?;
    toml::from_str(text).map_err(|_| ConfigError::Invalid)
}

/// Fails with [`ConfigError::RelativePath`] unless every path is absolute.
pub fn require_absolute(paths: &[&Path]) -> Result<(), ConfigError> {
    if paths.iter().all(|path| path.is_absolute()) {
        Ok(())
    } else {
        Err(ConfigError::RelativePath)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{ConfigError, load, require_absolute};

    #[derive(serde::Deserialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Sample {
        name: String,
    }

    #[test]
    fn loads_bounded_strict_toml() {
        let dir = std::env::temp_dir().join(format!("ov-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.toml");
        std::fs::write(&good, "name = \"ingest\"\n").unwrap();
        assert_eq!(
            load::<Sample>(&good).unwrap(),
            Sample {
                name: "ingest".into()
            }
        );
        let unknown = dir.join("unknown.toml");
        std::fs::write(&unknown, "name = \"x\"\nnmae = \"typo\"\n").unwrap();
        assert_eq!(load::<Sample>(&unknown).unwrap_err(), ConfigError::Invalid);
        let big = dir.join("big.toml");
        std::fs::write(&big, format!("name = \"{}\"\n", "x".repeat(64 * 1024))).unwrap();
        assert_eq!(load::<Sample>(&big).unwrap_err(), ConfigError::TooLarge);
        let binary = dir.join("binary.toml");
        std::fs::write(&binary, [0xff, 0xfe]).unwrap();
        assert_eq!(load::<Sample>(&binary).unwrap_err(), ConfigError::Invalid);
        assert_eq!(
            load::<Sample>(&dir.join("absent.toml")).unwrap_err(),
            ConfigError::Missing
        );
        assert_eq!(
            require_absolute(&[Path::new("rel/x")]).unwrap_err(),
            ConfigError::RelativePath
        );
        assert!(require_absolute(&[Path::new("/etc/x")]).is_ok());
    }
}
