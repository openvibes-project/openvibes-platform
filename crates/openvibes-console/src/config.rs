use std::{fmt, net::SocketAddr, path::Path};

use serde::Deserialize;

use crate::ConsoleError;

/// The deliberately limited C0 configuration.
///
/// Production TLS and trusted-proxy transports are added in the hardening
/// milestone. Until then, the public development listener is restricted to
/// loopback so an unfinished authentication stack cannot be exposed.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleConfig {
    /// Loopback-only, cleartext listener for C0 development.
    pub development_listen: SocketAddr,
    /// Separate loopback-only process health listener.
    pub health_listen: SocketAddr,
    /// Optional PostgreSQL pool URL; when paired, enables local C3 authentication.
    #[serde(default)]
    pub database_url: Option<String>,
    /// Canonical HTTP origin on loopback for local authentication development.
    #[serde(default)]
    pub public_origin: Option<String>,
}

impl fmt::Debug for ConsoleConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsoleConfig")
            .field("development_listen", &self.development_listen)
            .field("health_listen", &self.health_listen)
            .field(
                "database_url",
                &self.database_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("public_origin", &self.public_origin)
            .finish()
    }
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
        match (&self.database_url, &self.public_origin) {
            (None, None) => {}
            (Some(database_url), Some(public_origin))
                if !database_url.trim().is_empty() && valid_local_origin(public_origin) => {}
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
    use super::ConsoleConfig;

    #[test]
    fn accepts_separate_loopback_listeners() {
        let config = ConsoleConfig {
            development_listen: "127.0.0.1:8443".parse().unwrap(),
            health_listen: "127.0.0.1:18481".parse().unwrap(),
            database_url: None,
            public_origin: None,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_exposed_or_shared_listeners() {
        for config in [
            ConsoleConfig {
                development_listen: "0.0.0.0:8443".parse().unwrap(),
                health_listen: "127.0.0.1:18481".parse().unwrap(),
                database_url: None,
                public_origin: None,
            },
            ConsoleConfig {
                development_listen: "127.0.0.1:8443".parse().unwrap(),
                health_listen: "[::]:18481".parse().unwrap(),
                database_url: None,
                public_origin: None,
            },
            ConsoleConfig {
                development_listen: "127.0.0.1:8443".parse().unwrap(),
                health_listen: "127.0.0.1:8443".parse().unwrap(),
                database_url: None,
                public_origin: None,
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
            database_url: Some("postgresql://user:secret@localhost/console".into()),
            public_origin: Some("http://localhost:8443".into()),
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
