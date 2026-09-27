//! The configuration files the Configuration screen edits (admin TUI spec
//! §5), checked by each service's own configuration type, so the TUI and
//! the root helper accept exactly what the service will start with.

use platform_host::Service;
use serde::{Deserialize, de::DeserializeOwned};

/// Largest configuration file, as `platform_config::load` reads it.
pub const MAX_BYTES: usize = 64 * 1024;

/// `/etc/openvibes/admin.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// PostgreSQL connection for the `openvibes-admin` role.
    pub database_url: String,
}

fn parse<T: DeserializeOwned>(text: &str) -> Result<T, String> {
    // `message()`: the reason only, without the file excerpt.
    toml::from_str(text).map_err(|error: toml::de::Error| error.message().to_owned())
}

/// Parses `text` as `service`'s configuration and runs the service's checks.
pub fn validate(service: Service, text: &str) -> Result<(), String> {
    if text.len() > MAX_BYTES {
        return Err("the file would exceed 64 KiB".into());
    }
    match service {
        Service::Ingest => parse::<openvibes_ingest::IngestConfig>(text)?
            .validate()
            .map_err(|error| error.to_string()),
        Service::Distribution => parse::<openvibes_distribution::DistributionConfig>(text)?
            .validate()
            .map_err(|error| error.to_string()),
        Service::Vulns => parse::<openvibes_vulns::config::VulnsConfig>(text)?.validate(),
        Service::Console => parse::<openvibes_console::ConsoleConfig>(text)?
            .validate()
            .map_err(|error| error.to_string()),
        Service::Admin => parse::<AdminConfig>(text).map(drop),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use platform_host::Service;

    use super::validate;

    pub(crate) fn packaged(service: Service) -> &'static str {
        match service {
            Service::Ingest => include_str!("../../../packaging/rpm/ingest.toml"),
            Service::Distribution => include_str!("../../../packaging/rpm/distribution.toml"),
            Service::Vulns => include_str!("../../../packaging/rpm/vulns.toml"),
            Service::Console => include_str!("../../../packaging/rpm/console.toml"),
            Service::Admin => include_str!("../../../packaging/rpm/admin.toml"),
        }
    }

    #[test]
    fn packaged_files_are_valid() {
        for service in Service::ALL {
            assert_eq!(
                validate(service, packaged(service)),
                Ok(()),
                "{}",
                service.name()
            );
        }
    }

    #[test]
    fn unknown_keys_and_oversize_files_are_refused() {
        let error = validate(Service::Admin, "database_url = \"x\"\nextra = 1\n").unwrap_err();
        assert!(error.contains("unknown field"), "{error}");
        let big = format!("database_url = \"{}\"\n", "x".repeat(64 * 1024));
        assert_eq!(
            validate(Service::Admin, &big),
            Err("the file would exceed 64 KiB".into())
        );
    }

    #[test]
    fn range_errors_come_from_the_service() {
        let text = packaged(Service::Vulns)
            .replace("check_interval_minutes = 60", "check_interval_minutes = 5");
        assert_eq!(
            validate(Service::Vulns, &text),
            Err("check_interval_minutes must be 15 to 1440".into())
        );
        let text = format!(
            "{}max_inventory_in_flight = 200\n",
            packaged(Service::Ingest)
        );
        assert_eq!(
            validate(Service::Ingest, &text),
            Err("invalid ingest configuration".into())
        );
    }
}
