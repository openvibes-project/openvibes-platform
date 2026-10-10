//! The outbound HTTP client: short timeouts, no redirects, a size limit and
//! a host allowlist.

use std::time::Duration;

/// Largest response body accepted, in bytes.
pub const MAX_BODY: usize = 256 * 1024;

/// Hosts level 1 may contact. (The SearXNG host is added with web search.)
const HOSTS: [&str; 2] = ["api.osv.dev", "bodhi.fedoraproject.org"];

/// Fetches a URL; faked in tests.
pub trait Http {
    /// The response body of a GET (at most `MAX_BODY + 1` bytes), or why not.
    fn get(&self, url: &str) -> Result<Vec<u8>, String>;
}

/// True when `url` is `https://` + an allowed host + `/`.
pub fn allowed(url: &str) -> bool {
    url.strip_prefix("https://")
        .and_then(|r| r.split_once('/'))
        .is_some_and(|(host, _)| HOSTS.contains(&host))
}

/// The real client.
pub struct Client {
    agent: ureq::Agent,
}

impl Client {
    /// A client, through `proxy` when given.
    ///
    /// # Errors
    /// An invalid proxy URL.
    pub fn new(proxy: Option<&str>) -> Result<Self, String> {
        let proxy = proxy
            .map(ureq::Proxy::new)
            .transpose()
            .map_err(|_| "invalid proxy_url".to_owned())?;
        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(5)))
            .timeout_global(Some(Duration::from_secs(10)))
            .max_redirects(0)
            .proxy(proxy)
            .build();
        Ok(Self {
            agent: config.into(),
        })
    }
}

impl Http for Client {
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        if !allowed(url) {
            return Err("host not allowed".into());
        }
        // A 3xx is an error status here: redirects are never followed.
        let mut response = self
            .agent
            .get(url)
            .header("Accept", "application/json")
            .config()
            .http_status_as_error(false)
            .build()
            .call()
            .map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(format!("status {status}"));
        }
        response
            .body_mut()
            .with_config()
            .limit(MAX_BODY as u64 + 1)
            .read_to_vec()
            .map_err(|e| e.to_string())
    }
}
