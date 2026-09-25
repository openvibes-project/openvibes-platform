//! `/etc/openvibes/vulns.toml`.

use std::{net::SocketAddr, path::Path};

use serde::Deserialize;

use crate::fetch::{self, EPSS_URL, FEDORA_METALINK, Fetcher, KEV_URL};

fn default_health() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 18483))
}
fn default_interval() -> u64 {
    60
}
fn default_metalink() -> String {
    FEDORA_METALINK.to_owned()
}
fn default_arch() -> String {
    "x86_64".to_owned()
}
fn default_kev() -> String {
    KEV_URL.to_owned()
}
fn default_epss() -> String {
    EPSS_URL.to_owned()
}
fn default_download() -> u64 {
    64 << 20
}

/// Service configuration; unknown keys are refused.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VulnsConfig {
    /// PostgreSQL connection for the `openvibes_vulns` role.
    pub database_url: String,
    /// Loopback health listener (`/health`, `/ready`).
    #[serde(default = "default_health")]
    pub health_listen: SocketAddr,
    /// Minutes between feed checks, 15 to 1440 (a check downloads only
    /// when the feed changed).
    #[serde(default = "default_interval")]
    pub check_interval_minutes: u64,
    /// Mirror list template with `{release}` and `{arch}`; HTTPS.
    #[serde(default = "default_metalink")]
    pub metalink_url: String,
    /// Repository architecture fetched; its feed covers every architecture.
    #[serde(default = "default_arch")]
    pub arch: String,
    /// Outbound proxy, e.g. `http://proxy.example:3128`.
    #[serde(default)]
    pub proxy_url: Option<String>,
    /// Largest feed download (compressed), in bytes.
    #[serde(default = "default_download")]
    pub max_download_bytes: u64,
    /// CISA KEV catalog URL (HTTPS); empty turns it off.
    #[serde(default = "default_kev")]
    pub kev_url: String,
    /// FIRST EPSS scores URL (HTTPS); empty turns it off.
    #[serde(default = "default_epss")]
    pub epss_url: String,
}

impl VulnsConfig {
    /// Checks ranges and the trust rules (loopback health, HTTPS metalink).
    pub fn validate(&self) -> Result<(), String> {
        if !self.health_listen.ip().is_loopback() {
            return Err("health_listen must be a loopback address".into());
        }
        if !(15..=1440).contains(&self.check_interval_minutes) {
            return Err("check_interval_minutes must be 15 to 1440".into());
        }
        if !(1..=(1 << 30)).contains(&self.max_download_bytes) {
            return Err("max_download_bytes must be 1 to 1073741824".into());
        }
        if self.arch.is_empty()
            || !self
                .arch
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err("arch must be an architecture name like x86_64".into());
        }
        for url in [&self.kev_url, &self.epss_url] {
            if !url.is_empty() {
                fetch::check_source_url(url)?;
            }
        }
        Fetcher::new(
            &self.metalink_url,
            self.proxy_url.as_deref(),
            self.max_download_bytes,
        )
        .map(drop)
    }
}

/// Loads and validates the configuration file.
pub fn load_config(path: &Path) -> Result<VulnsConfig, String> {
    let config: VulnsConfig = platform_config::load(path).map_err(|error| error.to_string())?;
    config.validate()?;
    Ok(config)
}
