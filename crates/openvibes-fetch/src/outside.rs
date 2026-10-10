//! What the assistant's model sees of an internet lookup: the outside-data
//! shape and the fixed notes. One place for the console and the evaluation.

use serde_json::{Value, json};

use crate::protocol::Item;

/// Internet lookups are switched off (no failure).
pub const NOTE_OFF: &str = "internet lookups are off";
/// The query filter refused the lookup.
pub const NOTE_BLOCKED: &str = "blocked: the query contained internal data";
/// The per-user hourly limit is used up.
pub const NOTE_LIMIT: &str = "the internet lookup limit is reached; try again later";
/// The reference source failed.
pub const NOTE_REFERENCE_DOWN: &str = "OSV could not be reached; this answer uses local data only";
/// The web search failed.
pub const NOTE_SEARCH_DOWN: &str =
    "the web search could not be reached; this answer uses local data only";
/// The reference ID is not a public advisory or CVE ID (no failure).
pub const NOTE_INVALID: &str = "not a public advisory or CVE ID";

/// A note in place of a result.
pub fn note(text: &str) -> Value {
    json!({ "note": text })
}

/// Outside text as data for the model. Each item has a plain-text `ref`
/// label (`[web:N]`, numbered from `first`) and its URL as text; no key is
/// a citation key, so nothing outside can become a link in the answer.
pub fn data(source: &str, items: &[Item], first: usize) -> Value {
    let items: Vec<Value> = items
        .iter()
        .enumerate()
        .map(|(n, i)| {
            json!({ "ref": format!("[web:{}]", first + n), "title": i.title,
                    "snippet": i.snippet, "url": i.url })
        })
        .collect();
    json!({ "source": source, "outside_data": true, "items": items, "omitted": 0 })
}

/// The lowercase `host[:port]` of an `http(s)` URL (no user info, path or
/// query); `None` for any other URL or an odd host.
pub fn link_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#', '\\']).next()?;
    let host = authority.rsplit('@').next()?.to_ascii_lowercase();
    (!host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']')))
    .then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refs_are_numbered_from_first_and_hosts_come_from_http_urls_only() {
        let item = |url: &str| Item {
            title: "t".into(),
            snippet: "s".into(),
            url: url.into(),
        };
        let v = data("osv.dev", &[item("https://a/"), item("https://b/")], 3);
        assert_eq!(v["items"][0]["ref"], "[web:3]");
        assert_eq!(v["items"][1]["ref"], "[web:4]");
        assert_eq!(v["outside_data"], true);
        assert_eq!(note(NOTE_OFF)["note"], NOTE_OFF);
        for (url, host) in [
            ("https://Osv.dev/vulnerability/X", Some("osv.dev")),
            ("http://b.example:8080?q=1", Some("b.example:8080")),
            ("https://user@evil.example/x", Some("evil.example")),
            ("javascript:alert(1)", None),
            ("https:///x", None),
            ("https://a b/", None),
        ] {
            assert_eq!(link_host(url).as_deref(), host, "{url}");
        }
    }
}
