use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::ConsoleError;

/// Public-listener transport selected by the operator.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConsoleTransportMode {
    /// Loopback-only cleartext mode for local development.
    #[default]
    Development,
    /// TLS 1.3 terminates in the console process.
    DirectTls,
    /// Cleartext loopback upstream behind explicitly trusted local proxies.
    ReverseProxy,
}

/// Strict configuration for the console public and health listeners.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleConfig {
    /// TCP listener for development, direct TLS, or TCP proxy mode; unused with a Unix socket.
    pub development_listen: SocketAddr,
    /// Separate loopback-only process health listener.
    pub health_listen: SocketAddr,
    /// Explicit public listener transport.
    #[serde(default)]
    pub transport_mode: ConsoleTransportMode,
    /// Optional PostgreSQL pool URL; when paired, enables local C3 authentication.
    #[serde(default)]
    pub database_url: Option<String>,
    /// Canonical HTTP origin on loopback for local authentication development.
    #[serde(default)]
    pub public_origin: Option<String>,
    /// Absolute PEM server certificate chain for direct TLS 1.3.
    #[serde(default)]
    pub server_certificate_file: Option<PathBuf>,
    /// Absolute PEM server private key for direct TLS 1.3.
    #[serde(default)]
    pub server_key_file: Option<PathBuf>,
    /// Exact loopback IP addresses allowed to connect in reverse-proxy mode.
    #[serde(default)]
    pub trusted_proxy_addresses: Vec<IpAddr>,
    /// Absolute Unix socket path used instead of `development_listen` in proxy mode.
    #[serde(default)]
    pub unix_socket_file: Option<PathBuf>,
    /// Exact Unix effective UIDs allowed to connect to `unix_socket_file`.
    #[serde(default)]
    pub trusted_proxy_uids: Vec<u32>,
}

impl fmt::Debug for ConsoleConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsoleConfig")
            .field("development_listen", &self.development_listen)
            .field("health_listen", &self.health_listen)
            .field("transport_mode", &self.transport_mode)
            .field(
                "database_url",
                &self.database_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("public_origin", &self.public_origin)
            .field("server_certificate_file", &self.server_certificate_file)
            .field("server_key_file", &self.server_key_file)
            .field("trusted_proxy_addresses", &self.trusted_proxy_addresses)
            .field("unix_socket_file", &self.unix_socket_file)
            .field("trusted_proxy_uids", &self.trusted_proxy_uids)
            .finish()
    }
}

impl ConsoleConfig {
    /// Rejects unsafe transport combinations and shared public/health binds.
    pub fn validate(&self) -> Result<(), ConsoleError> {
        let tls_configured = self.transport_mode == ConsoleTransportMode::DirectTls;
        let tls_paths_valid = match (&self.server_certificate_file, &self.server_key_file) {
            (None, None) if !tls_configured => true,
            (Some(certificate), Some(key))
                if tls_configured && certificate.is_absolute() && key.is_absolute() =>
            {
                true
            }
            _ => false,
        };
        let proxy_mode = self.transport_mode == ConsoleTransportMode::ReverseProxy;
        let proxy_addresses_valid = if proxy_mode {
            let tcp_valid = !self.trusted_proxy_addresses.is_empty()
                && self.trusted_proxy_addresses.len() <= 64
                && self
                    .trusted_proxy_addresses
                    .iter()
                    .all(|address| address.is_loopback())
                && self
                    .trusted_proxy_addresses
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    == self.trusted_proxy_addresses.len()
                && self.unix_socket_file.is_none()
                && self.trusted_proxy_uids.is_empty();
            let unix_valid = self.trusted_proxy_addresses.is_empty()
                && self
                    .unix_socket_file
                    .as_ref()
                    .is_some_and(|path| path.is_absolute())
                && !self.trusted_proxy_uids.is_empty()
                && self.trusted_proxy_uids.len() <= 64
                && self
                    .trusted_proxy_uids
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    == self.trusted_proxy_uids.len();
            tcp_valid || unix_valid
        } else {
            self.trusted_proxy_addresses.is_empty()
                && self.unix_socket_file.is_none()
                && self.trusted_proxy_uids.is_empty()
        };
        if !tls_paths_valid
            || !proxy_addresses_valid
            || !self.health_listen.ip().is_loopback()
            || (self.unix_socket_file.is_none() && self.development_listen == self.health_listen)
            || (self.transport_mode != ConsoleTransportMode::DirectTls
                && self.unix_socket_file.is_none()
                && !self.development_listen.ip().is_loopback())
        {
            return Err(ConsoleError::Config);
        }
        match (&self.database_url, &self.public_origin) {
            (None, None) if self.transport_mode == ConsoleTransportMode::Development => {}
            (Some(database_url), Some(public_origin))
                if !database_url.trim().is_empty()
                    && match self.transport_mode {
                        ConsoleTransportMode::Development => valid_local_origin(public_origin),
                        ConsoleTransportMode::DirectTls | ConsoleTransportMode::ReverseProxy => {
                            valid_public_origin(public_origin)
                                && public_origin.starts_with("https://")
                        }
                    } => {}
            _ => return Err(ConsoleError::Config),
        }
        Ok(())
    }
}

pub(crate) fn valid_public_origin(origin: &str) -> bool {
    let Ok(uri) = origin.parse::<axum::http::Uri>() else {
        return false;
    };
    let Some(scheme) = uri.scheme_str() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    let Some((_, raw_authority)) = origin.split_once("://") else {
        return false;
    };
    if raw_authority.contains(['/', '?', '#'])
        || uri
            .path_and_query()
            .is_some_and(|path| path.as_str() != "/")
        || authority.as_str().contains('@')
        || origin != origin.to_ascii_lowercase()
    {
        return false;
    }
    match scheme {
        "https" => true,
        "http" => loopback_host(authority.as_str()),
        _ => false,
    }
}

fn valid_local_origin(origin: &str) -> bool {
    if !valid_public_origin(origin) {
        return false;
    }
    origin.parse::<axum::http::Uri>().ok().is_some_and(|uri| {
        uri.scheme_str() == Some("http")
            && uri
                .authority()
                .is_some_and(|authority| loopback_host(authority.as_str()))
    })
}

fn loopback_host(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map_or("", |(name, _)| name),
        None => host.rsplit_once(':').map_or(host, |(name, _)| name),
    };
    name.eq_ignore_ascii_case("localhost") || name == "127.0.0.1" || name == "::1"
}

/// Loads and validates a C0 console configuration file.
pub fn load_config(path: &Path) -> Result<ConsoleConfig, ConsoleError> {
    let config: ConsoleConfig = platform_config::load(path).map_err(|_| ConsoleError::Config)?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::{ConsoleConfig, ConsoleTransportMode};

    #[test]
    fn accepts_separate_loopback_listeners() {
        let config = ConsoleConfig {
            development_listen: "127.0.0.1:8443".parse().unwrap(),
            health_listen: "127.0.0.1:18481".parse().unwrap(),
            transport_mode: ConsoleTransportMode::Development,
            database_url: None,
            public_origin: None,
            server_certificate_file: None,
            server_key_file: None,
            trusted_proxy_addresses: vec![],
            unix_socket_file: None,
            trusted_proxy_uids: vec![],
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_exposed_or_shared_listeners() {
        for config in [
            ConsoleConfig {
                development_listen: "0.0.0.0:8443".parse().unwrap(),
                health_listen: "127.0.0.1:18481".parse().unwrap(),
                transport_mode: ConsoleTransportMode::Development,
                database_url: None,
                public_origin: None,
                server_certificate_file: None,
                server_key_file: None,
                trusted_proxy_addresses: vec![],
                unix_socket_file: None,
                trusted_proxy_uids: vec![],
            },
            ConsoleConfig {
                development_listen: "127.0.0.1:8443".parse().unwrap(),
                health_listen: "[::]:18481".parse().unwrap(),
                transport_mode: ConsoleTransportMode::Development,
                database_url: None,
                public_origin: None,
                server_certificate_file: None,
                server_key_file: None,
                trusted_proxy_addresses: vec![],
                unix_socket_file: None,
                trusted_proxy_uids: vec![],
            },
            ConsoleConfig {
                development_listen: "127.0.0.1:8443".parse().unwrap(),
                health_listen: "127.0.0.1:8443".parse().unwrap(),
                transport_mode: ConsoleTransportMode::Development,
                database_url: None,
                public_origin: None,
                server_certificate_file: None,
                server_key_file: None,
                trusted_proxy_addresses: vec![],
                unix_socket_file: None,
                trusted_proxy_uids: vec![],
            },
        ] {
            assert!(config.validate().is_err());
        }
    }

    #[test]
    fn authentication_config_is_paired_redacted_and_loopback_safe() {
        let valid = ConsoleConfig {
            development_listen: "127.0.0.1:8443".parse().unwrap(),
            health_listen: "127.0.0.1:18481".parse().unwrap(),
            transport_mode: ConsoleTransportMode::Development,
            database_url: Some("postgresql://user:secret@localhost/console".into()),
            public_origin: Some("http://localhost:8443".into()),
            server_certificate_file: None,
            server_key_file: None,
            trusted_proxy_addresses: vec![],
            unix_socket_file: None,
            trusted_proxy_uids: vec![],
        };
        assert!(valid.validate().is_ok());
        assert!(!format!("{valid:?}").contains("secret"));

        let invalid = ConsoleConfig {
            database_url: Some("postgresql://localhost/console".into()),
            public_origin: None,
            ..valid.clone()
        };
        assert!(invalid.validate().is_err());
        for origin in [
            "null",
            "http://console.example",
            "https://console.example/path",
        ] {
            let invalid = ConsoleConfig {
                database_url: Some("postgresql://localhost/console".into()),
                public_origin: Some(origin.into()),
                ..valid.clone()
            };
            assert!(invalid.validate().is_err());
        }
    }
}
