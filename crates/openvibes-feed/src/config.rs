//! `/etc/openvibes/feed.toml`: which upstream data a site's feed carries. The
//! builder has no database, so the releases the site runs are listed here.

use std::path::Path;

use serde::Deserialize;

/// The builder's settings; every key is optional.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Fedora repositories, as `fedora-<release>-<arch>`.
    pub fedora: Vec<String>,
    /// OSV releases (`debian-12`, `ubuntu-24.04`, `rocky-9`, `almalinux-9`).
    pub osv_releases: Vec<String>,
    /// Mirror list template for Fedora (`{release}`, `{arch}`); must return a metalink.
    pub metalink_url: String,
    /// OSV.dev bucket; `""` leaves OSV out.
    pub osv_url: String,
    /// CISA KEV; `""` leaves it out.
    pub kev_url: String,
    /// FIRST EPSS; `""` leaves it out.
    pub epss_url: String,
    /// ENISA EUVD search API; `""` leaves it out.
    pub euvd_url: String,
    /// NVD CVE API 2.0; `""` leaves NVD (and CPE findings from a feed) out.
    pub nvd_url: String,
    /// A file holding an NVD API key (as in `vulns.toml`): with one the builder
    /// asks NVD every 0.6 s instead of every 6 s.
    pub nvd_api_key_file: Option<String>,
    /// Pause between NVD requests, in milliseconds (default: NVD's published limit).
    pub nvd_pause_ms: Option<u64>,
    /// HTTP proxy for every download.
    pub proxy_url: Option<String>,
    /// Days a feed stays valid.
    pub valid_days: u32,
    /// Largest body read for one small file (updateinfo, KEV, EPSS, EUVD), in bytes.
    pub max_file_bytes: u64,
    /// Largest OSV `all.zip`, in bytes.
    pub max_osv_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            fedora: Vec::new(),
            osv_releases: Vec::new(),
            metalink_url: openvibes_vulns::fetch::FEDORA_METALINK.to_owned(),
            osv_url: openvibes_vulns::osv_fetch::OSV_URL.to_owned(),
            kev_url: openvibes_vulns::fetch::KEV_URL.to_owned(),
            epss_url: openvibes_vulns::fetch::EPSS_URL.to_owned(),
            euvd_url: openvibes_vulns::sources::EUVD_URL.to_owned(),
            nvd_url: openvibes_vulns::sources::NVD_URL.to_owned(),
            nvd_api_key_file: None,
            nvd_pause_ms: None,
            proxy_url: None,
            valid_days: 7,
            max_file_bytes: 512 << 20,
            max_osv_bytes: 4 << 30,
        }
    }
}

/// Reads the settings; a missing file means the defaults.
///
/// # Errors
/// The file exists but cannot be read or is not valid.
pub fn load(path: &Path) -> Result<Config, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let config: Config = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if !(1..=30).contains(&config.valid_days) {
        return Err("valid_days is 1 to 30".into());
    }
    Ok(config)
}
