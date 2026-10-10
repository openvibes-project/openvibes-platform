//! Extracts a Fedora Bodhi update (`/updates/{alias}`) by JSON path.

use crate::{cut, protocol::Item, snippet};
use serde_json::Value;

/// One item: the update title, its notes cut to 1,000 characters plus
/// `fixed in <build NVRs>`, and the update page. `None` when `v` is no update.
pub fn extract(id: &str, v: &Value) -> Option<Vec<Item>> {
    let u = v.get("update")?;
    let s = |k: &str| u.get(k).and_then(Value::as_str).unwrap_or("");
    let nvrs: Vec<String> = u
        .get("builds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|b| b.get("nvr").and_then(Value::as_str))
        .map(|n| cut(n, 100))
        .take(10)
        .collect();
    let tail = if nvrs.is_empty() {
        String::new()
    } else {
        format!("\nfixed in {}", nvrs.join(", "))
    };
    let title = match s("title") {
        "" => id.to_owned(),
        t => cut(t, 200),
    };
    Some(vec![Item {
        title,
        snippet: snippet(s("notes"), &tail),
        url: format!("https://bodhi.fedoraproject.org/updates/{id}"),
    }])
}
