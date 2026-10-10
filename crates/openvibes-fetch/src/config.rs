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
}
