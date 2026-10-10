//! Web search through the administrator's SearXNG: builds the request URL
//! and extracts a bounded result list from its JSON.

use crate::{cut, protocol::Item};
use serde_json::Value;
use std::net::IpAddr;

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

/// `https://` to any host; `http://` only to loopback or a private address.
/// No user info, query, fragment, whitespace or control characters.
pub fn valid_url(url: &str) -> bool {
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return false;
    };
    if url.contains(['?', '#', '@']) || url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or("");
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((host, after)) => (host, after.strip_prefix(':')),
            None => return false,
        },
        None => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    if host.is_empty() || port.is_some_and(|p| p.parse::<u16>().map_or(true, |p| p == 0)) {
        return false;
    }
    https || host.eq_ignore_ascii_case("localhost") || host.parse::<IpAddr>().is_ok_and(private_ip)
}

/// True when the stored URL is plain `http://` or names a loopback or
/// private IP literal: such a SearXNG is reached directly, never through
/// the external proxy.
pub fn is_local(base: &str) -> bool {
    base.starts_with("http://")
        || host(base)
            .rsplit_once(':')
            .map_or(host(base), |(h, _)| h.to_owned())
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(private_ip)
}

fn private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
    }
}
