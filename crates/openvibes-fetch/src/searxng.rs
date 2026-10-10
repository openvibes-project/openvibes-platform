//! Web search through the administrator's SearXNG: builds the request URL
//! and extracts a bounded result list from its JSON.

use crate::{cut, protocol::Item};
use serde_json::Value;

/// `{base}/search?q=<query>&format=json`, whether or not `base` ends in `/`.
pub fn search_url(base: &str, query: &str) -> String {
    let mut q = String::new();
    for b in query.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            q.push(char::from(b));
        } else {
            q.push_str(&format!("%{b:02X}"));
        }
    }
    format!("{}/search?q={q}&format=json", base.trim_end_matches('/'))
}

/// `host[:port]` of `base`, shown as the source.
pub fn host(base: &str) -> String {
    let rest = base.split_once("://").map_or(base, |(_, r)| r);
    rest.split('/').next().unwrap_or(rest).to_owned()
}

/// Up to five results with an http(s) URL (`javascript:`, `data:` and the
/// like are dropped); title cut to 200, snippet to 300 characters. `None`
/// when `v` has no `results` array.
pub fn extract(v: &Value) -> Option<Vec<Item>> {
    let results = v.get("results")?.as_array()?;
    let text = |r: &Value, k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    Some(
        results
            .iter()
            .filter_map(|r| {
                let url = text(r, "url");
                let web = url.starts_with("https://") || url.starts_with("http://");
                web.then(|| Item {
                    title: cut(&text(r, "title"), 200),
                    snippet: cut(&text(r, "content"), 300),
                    url: cut(&url, 500),
                })
            })
            .take(5)
            .collect(),
    )
}
