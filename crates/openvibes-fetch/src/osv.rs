//! Extracts an OSV record (`https://api.osv.dev/v1/vulns/{id}`) by JSON path.

use crate::{cut, protocol::Item};
use serde_json::Value;

/// One item for the record (title: id and first summary line; snippet: the
/// summary or details cut to 1,000 characters, then one
/// `package: fixed in a, b` line per affected package), then up to five
/// reference URLs as further items titled `reference`. `None` when `v` is no
/// OSV record.
pub fn extract(id: &str, v: &Value) -> Option<Vec<Item>> {
    v.get("id")?;
    let text = |k: &str| v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty());
    let summary = text("summary");
    let first = summary.or(text("details")).and_then(|s| s.lines().next());
    let title = match first {
        Some(l) => format!("{id}: {}", cut(l, 200)),
        None => id.to_owned(),
    };
    let mut snippet = cut(summary.or(text("details")).unwrap_or(""), 1000);
    for a in v.get("affected").and_then(Value::as_array)? {
        let Some(name) = a.pointer("/package/name").and_then(Value::as_str) else {
            continue; // git-only ranges carry commit hashes, not versions
        };
        let mut fixed: Vec<&str> = Vec::new();
        for r in a
            .get("ranges")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for e in r
                .get("events")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(f) = e.get("fixed").and_then(Value::as_str)
                    && !fixed.contains(&f)
                    && fixed.len() < 10
                {
                    fixed.push(f);
                }
            }
        }
        if !fixed.is_empty() {
            snippet.push_str(&format!(
                "\n{}: fixed in {}",
                cut(name, 100),
                fixed.join(", ")
            ));
        }
    }
    let mut items = vec![Item {
        title,
        snippet,
        url: format!("https://osv.dev/vulnerability/{id}"),
    }];
    for r in v
        .get("references")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(u) = r.get("url").and_then(Value::as_str)
            && u.starts_with("https://")
            && items.len() < 6
        {
            items.push(Item {
                title: "reference".into(),
                snippet: String::new(),
                url: cut(u, 500),
            });
        }
    }
    Some(items)
}
