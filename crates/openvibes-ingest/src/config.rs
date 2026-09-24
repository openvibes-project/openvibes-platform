use std::{net::SocketAddr, path::PathBuf};

use serde::Deserialize;

use crate::IngestError;

fn default_days() -> u32 {
    30
}
fn default_in_flight() -> usize {
    4096
}
fn default_retention() -> u32 {
    90
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

/// `/etc/openvibes/ingest.toml` (spec section 3).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestConfig {
    /// Agent-facing TLS listener.
    pub listen: SocketAddr,
    /// Loopback health listener (`/health`, `/ready`).
    pub health_listen: SocketAddr,
    /// Server certificate chain, leaf first.
    pub server_certificate_file: PathBuf,
    /// Server private key.
    pub server_key_file: PathBuf,
    /// CA that issued accepted client certificates.
    pub client_ca_file: PathBuf,
    /// Intermediate that signs agent certificates.
    pub issuing_certificate_file: PathBuf,
    /// Its private key (0600, ingest user only).
    pub issuing_key_file: PathBuf,
    /// PostgreSQL connection for the `openvibes_ingest` role.
    pub database_url: String,
    /// Agent certificate lifetime, 1 to 365 days.
    #[serde(default = "default_days")]
    pub client_certificate_days: u32,
    /// Requests served at once; above this, 503.
    #[serde(default = "default_in_flight")]
    pub max_in_flight: usize,
    /// Findings older than this are acknowledged without storing (1 to
    /// 36500; must match `openvibes-admin maintenance --retention-days`).
    #[serde(default = "default_retention")]
    pub finding_retention_days: u32,
    /// Deadline for the TLS handshake, the request headers, and each whole
    /// request, 1 to 300 seconds.
    #[serde(default = "default_timeout")]
    pub request_timeout_seconds: u64,
    /// Open client connections at once, 1 to 65536; further connections
    /// wait in the kernel backlog. Keep below the process's file limit.
    #[serde(default = "default_connections")]
    pub max_connections: usize,
    /// Database connections, 1 to 1024.
    #[serde(default = "default_pool")]
    pub database_pool_size: usize,
}

impl IngestConfig {
    /// Rejects relative paths and out-of-range values.
    pub fn validate(&self) -> Result<(), IngestError> {
        self.settings()
            .validate()
            .map_err(|_| IngestError::Config)?;
        platform_config::require_absolute(&[
            &self.issuing_certificate_file,
            &self.issuing_key_file,
        ])
        .map_err(|_| IngestError::Config)?;
        let valid = (1..=365).contains(&self.client_certificate_days)
            && (1..=36_500).contains(&self.finding_retention_days);
        if valid {
            Ok(())
        } else {
            Err(IngestError::Config)
        }
    }
}

impl IngestConfig {
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
}

/// Loads and validates the configuration file.
pub fn load_config(path: &std::path::Path) -> Result<IngestConfig, IngestError> {
    let config: IngestConfig = platform_config::load(path).map_err(|_| IngestError::Config)?;
    config.validate()?;
    Ok(config)
}
