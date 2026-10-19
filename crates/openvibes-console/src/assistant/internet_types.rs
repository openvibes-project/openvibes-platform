use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The assistant's internet-lookup setting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AssistantInternet {
    /// 0 off, 1 security references (OSV, Bodhi), 2 those and web search through SearXNG.
    pub level: u8,
    /// SearXNG base URL, required at level 2.
    pub searxng_url: Option<String>,
    /// Extra internal domain names the outbound filter refuses.
    pub internal_domains: Vec<String>,
    /// Host of the console's public origin; always filtered.
    pub platform_domain: String,
    /// Version for conditional updates.
    pub version: u64,
    /// RFC 3339 update instant.
    pub updated_at: String,
    /// Local user id that last changed the setting.
    pub updated_by: String,
}

/// The outcome of a Test connection against the stored SearXNG.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct AssistantInternetTest {
    /// True when the search ran and answered.
    pub ok: bool,
    /// `N results`, or why not (off, blocked, unreachable).
    pub detail: String,
}

/// Request body for changing the assistant internet setting.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateAssistantInternetRequest {
    /// 0 off, 1 security references (OSV, Bodhi), 2 those and web search.
    #[schema(minimum = 0, maximum = 2)]
    pub level: u8,
    /// SearXNG base URL: `https://`, or `http://` on a local or private address.
    pub searxng_url: Option<String>,
    /// Lowercase internal domain names, at most 50.
    pub internal_domains: Vec<String>,
}
