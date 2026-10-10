//! `/etc/openvibes/netlog.toml`.

use std::{net::SocketAddr, path::Path};

use serde::Deserialize;

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 514))
}
fn default_health() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 18484))
}
fn default_batch() -> u64 {
    5
}
fn default_collapse() -> u64 {
    10
}
fn default_keys() -> usize {
    2000
}

/// Service configuration; unknown keys are refused.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetlogConfig {
    /// PostgreSQL connection for the `openvibes-netlog` role.
    pub database_url: String,
    /// UDP syslog listener.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Loopback health listener (`/health`, `/ready`).
    #[serde(default = "default_health")]
    pub health_listen: SocketAddr,
    #[serde(default = "default_batch")]
    pub batch_seconds: u64,
    #[serde(default = "default_collapse")]
    pub collapse_minutes: u64,
    #[serde(default = "default_keys")]
    pub max_collapse_keys: usize,
}

impl NetlogConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.health_listen.ip().is_loopback() {
            return Err("health_listen must be a loopback address".into());
        }
        if !(1..=60).contains(&self.batch_seconds) {
            return Err("batch_seconds must be 1 to 60".into());
        }
        if !(1..=1440).contains(&self.collapse_minutes) {
            return Err("collapse_minutes must be 1 to 1440".into());
        }
        // The unit's MemoryMax=64M holds about 5,000 (each open alarm is
        // ~7 KB at its largest, measured); more would get netlog killed.
        if !(1..=5000).contains(&self.max_collapse_keys) {
            return Err("max_collapse_keys must be 1 to 5000".into());
        }
        Ok(())
    }
}

pub fn load_config(path: &Path) -> Result<NetlogConfig, String> {
    let config: NetlogConfig = platform_config::load(path).map_err(|error| error.to_string())?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_ranges() {
        let c: NetlogConfig = toml_from("database_url = \"postgresql:///x\"");
        assert_eq!(
            (c.listen.port(), c.health_listen.port(), c.max_collapse_keys),
            (514, 18484, 2000)
        );
        assert!(c.validate().is_ok());
        let mut bad = c.clone();
        bad.health_listen = "0.0.0.0:18484".parse().unwrap();
        assert!(bad.validate().is_err());
        let mut bad = c.clone();
        bad.batch_seconds = 0;
        assert!(bad.validate().is_err());
        // The unit's MemoryMax=64M holds about 5,000 open alarms (2,000
        // measured at 20 MB under a flood); more would get it killed.
        let mut most = c.clone();
        most.max_collapse_keys = 5000;
        assert!(most.validate().is_ok());
        let mut bad = c;
        bad.max_collapse_keys = 5001;
        assert!(bad.validate().is_err());
    }

    fn toml_from(s: &str) -> NetlogConfig {
        let dir = std::env::temp_dir().join(format!("netlog-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("netlog.toml");
        std::fs::write(&path, s).unwrap();
        let c = platform_config::load(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        c
    }
}
