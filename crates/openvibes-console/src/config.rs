use std::{net::SocketAddr, path::Path};

use serde::Deserialize;

use crate::ConsoleError;

/// The deliberately limited C0 configuration.
///
/// Production TLS and trusted-proxy transports are added in the hardening
/// milestone. Until then, the public development listener is restricted to
/// loopback so an unfinished authentication stack cannot be exposed.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleConfig {
    /// Loopback-only, cleartext listener for C0 development.
    pub development_listen: SocketAddr,
    /// Separate loopback-only process health listener.
    pub health_listen: SocketAddr,
}

impl ConsoleConfig {
    /// Rejects any configuration that would expose a C0 listener or bind the
    /// two routers to the same address.
    pub fn validate(&self) -> Result<(), ConsoleError> {
        if !self.development_listen.ip().is_loopback()
            || !self.health_listen.ip().is_loopback()
            || self.development_listen == self.health_listen
        {
            return Err(ConsoleError::Config);
        }
        Ok(())
    }
}

/// Loads and validates a C0 console configuration file.
pub fn load_config(path: &Path) -> Result<ConsoleConfig, ConsoleError> {
    let config: ConsoleConfig = platform_config::load(path).map_err(|_| ConsoleError::Config)?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::ConsoleConfig;

    #[test]
    fn accepts_separate_loopback_listeners() {
        let config = ConsoleConfig {
            development_listen: "127.0.0.1:8443".parse().unwrap(),
            health_listen: "127.0.0.1:18481".parse().unwrap(),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_exposed_or_shared_listeners() {
        for config in [
            ConsoleConfig {
                development_listen: "0.0.0.0:8443".parse().unwrap(),
                health_listen: "127.0.0.1:18481".parse().unwrap(),
            },
            ConsoleConfig {
                development_listen: "127.0.0.1:8443".parse().unwrap(),
                health_listen: "[::]:18481".parse().unwrap(),
            },
            ConsoleConfig {
                development_listen: "127.0.0.1:8443".parse().unwrap(),
                health_listen: "127.0.0.1:8443".parse().unwrap(),
            },
        ] {
            assert!(config.validate().is_err());
        }
    }
}
