//! `/etc/openvibes/fetch.toml`.

use serde::Deserialize;

/// The fetcher's configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchConfig {
    /// PostgreSQL connection for the `openvibes-fetch` role.
    pub database_url: String,
    /// Optional outbound HTTP proxy.
    #[serde(default)]
    pub proxy_url: Option<String>,
    /// The console's public host name, written by Setup; never searched for.
    #[serde(default)]
    pub platform_domain: Option<String>,
}

impl FetchConfig {
    /// Deny-list terms for the platform's own name: the host and, when it
    /// is itself a domain (has a dot), its parent (`example.com` for
    /// `vibes.example.com`).
    pub fn platform_names(&self) -> Vec<String> {
        let Some(host) = self.platform_domain.as_deref().map(str::to_lowercase) else {
            return Vec::new();
        };
        let parent = host
            .split_once('.')
            .map(|(_, p)| p.to_owned())
            .filter(|p| p.contains('.'));
        std::iter::once(host).chain(parent).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::FetchConfig;

    #[test]
    fn the_platform_domain_is_optional_and_denies_the_host_and_its_parent() {
        let shipped: FetchConfig =
            toml::from_str(include_str!("../../../packaging/rpm/fetch.toml")).unwrap();
        assert!(shipped.platform_names().is_empty());
        let set: FetchConfig = toml::from_str(
            "database_url = \"postgresql:///x\"\nplatform_domain = \"Platform.Example.com\"\n",
        )
        .unwrap();
        assert_eq!(
            set.platform_names(),
            ["platform.example.com", "example.com"]
        );
        let short: FetchConfig =
            toml::from_str("database_url = \"x\"\nplatform_domain = \"vibes.lan\"\n").unwrap();
        // A bare top-level label (`lan`) is no domain of ours.
        assert_eq!(short.platform_names(), ["vibes.lan"]);
    }
}
