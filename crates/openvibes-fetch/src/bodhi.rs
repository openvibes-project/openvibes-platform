//! Extracts a Fedora Bodhi update (`/updates/{alias}`) by JSON path.

use crate::{cut, protocol::Item};
use serde_json::Value;

/// One item: the update title, its notes cut to 1,000 characters plus
/// `fixed in <build NVRs>`, and the update page. `None` when `v` is no update.
pub fn extract(id: &str, v: &Value) -> Option<Vec<Item>> {
    let u = v.get("update")?;
    let s = |k: &str| u.get(k).and_then(Value::as_str).unwrap_or("");
    let mut snippet = cut(s("notes"), 1000);
    let nvrs: Vec<&str> = u
        .get("builds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|b| b.get("nvr").and_then(Value::as_str))
        .take(10)
        .collect();
    if !nvrs.is_empty() {
        snippet.push_str(&format!("\nfixed in {}", nvrs.join(", ")));
    }
    let title = match s("title") {
        "" => id.to_owned(),
        t => cut(t, 200),
    };
    Some(vec![Item {
        title,
        snippet,
        url: format!("https://bodhi.fedoraproject.org/updates/{id}"),
    }])
}
