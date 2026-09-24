use std::{net::SocketAddr, path::PathBuf};

use serde::Deserialize;

use crate::DistributionError;

fn default_in_flight() -> usize {
    4096
}
fn default_timeout() -> u64 {
    10
}
fn default_connections() -> usize {
    1024
}
fn default_pool() -> usize {
    16
}

/// `/etc/openvibes/distribution.toml` (SP2 spec section 4).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionConfig {
    /// Agent-facing TLS listener (default port 18424).
    pub listen: SocketAddr,
    /// Loopback health listener (`/health`, `/ready`).
    pub health_listen: SocketAddr,
    /// Server certificate chain, leaf first.
    pub server_certificate_file: PathBuf,
    /// Server private key.
    pub server_key_file: PathBuf,
    /// CA that issued accepted client certificates.
    pub client_ca_file: PathBuf,
    /// PostgreSQL connection for the `openvibes_distribution` role.
    pub database_url: String,
    /// Requests served at once; above this, 503.
    #[serde(default = "default_in_flight")]
    pub max_in_flight: usize,
    /// Deadline for the TLS handshake, the request headers, and each whole
    /// request, 1 to 300 seconds.
    #[serde(default = "default_timeout")]
    pub request_timeout_seconds: u64,
    /// Open client connections at once, 1 to 65536.
    #[serde(default = "default_connections")]
    pub max_connections: usize,
    /// Database connections, 1 to 1024.
    #[serde(default = "default_pool")]
    pub database_pool_size: usize,
}

impl DistributionConfig {
    /// The fields the shared agent server needs.
    pub fn settings(&self) -> platform_agent_server::Settings {
        platform_agent_server::Settings {
            listen: self.listen,
            health_listen: self.health_listen,
            server_certificate_file: self.server_certificate_file.clone(),
            server_key_file: self.server_key_file.clone(),
            client_ca_file: self.client_ca_file.clone(),
            database_url: self.database_url.clone(),
            max_in_flight: self.max_in_flight,
            request_timeout_seconds: self.request_timeout_seconds,
            max_connections: self.max_connections,
            database_pool_size: self.database_pool_size,
        }
    }

    /// Rejects relative paths, a non-loopback health listener, and
    /// out-of-range values.
    pub fn validate(&self) -> Result<(), DistributionError> {
        self.settings()
            .validate()
            .map_err(|_| DistributionError::Config)
    }
}

/// Loads and validates the configuration file.
pub fn load_config(path: &std::path::Path) -> Result<DistributionConfig, DistributionError> {
    let config: DistributionConfig =
        platform_config::load(path).map_err(|_| DistributionError::Config)?;
    config.validate()?;
    Ok(config)
}
