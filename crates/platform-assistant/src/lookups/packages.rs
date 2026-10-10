//! A vulnerable host's packages for the model: the ones with a fix first,
//! capped, so a long list cannot push the host row out of the result.

use serde_json::Value;

/// Most packages shown per host.
const MAX_PACKAGES: usize = 10;

/// `packages` (`[{name, installed, fixed}]`) with fixed entries first, at
/// most [`MAX_PACKAGES`], and the count left out.
pub(super) fn capped(packages: &Value) -> (Value, usize) {
    let all = packages.as_array().map_or(&[][..], Vec::as_slice);
    let mut sorted: Vec<&Value> = all.iter().collect();
    sorted.sort_by_key(|p| p["fixed"].is_null()); // stable: fixed ones first
    let shown = sorted.into_iter().take(MAX_PACKAGES).cloned().collect();
    (Value::Array(shown), all.len().saturating_sub(MAX_PACKAGES))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::lookups::LookupOutput;

    fn many() -> Value {
        let mut list: Vec<Value> = (0..200)
            .map(|n| json!({ "name": format!("pkg{n}"), "installed": "1.0", "fixed": null }))
            .collect();
        list.push(json!({ "name": "openssh", "installed": "9.6", "fixed": "9.8" }));
        Value::Array(list)
    }

    #[test]
    fn fixed_entries_come_first_and_the_rest_is_counted() {
        let (shown, omitted) = capped(&many());
        let shown = shown.as_array().unwrap();
        assert_eq!(shown.len(), MAX_PACKAGES);
        assert_eq!(shown[0]["name"], "openssh");
        assert_eq!(shown[0]["fixed"], "9.8");
        assert_eq!(omitted, 201 - MAX_PACKAGES);
    }

    #[test]
    fn a_host_with_200_packages_still_survives_the_result_budget() {
        let (shown, omitted) = capped(&many());
        let row =
            json!({ "cite": "[agent:agent.1]", "packages": shown, "packages_omitted": omitted });
        let mut out = LookupOutput::page(serde_json::Map::new(), vec![row], 1);
        out.shrink_to(1_600);
        assert_eq!(out.data["items"].as_array().unwrap().len(), 1);
        assert_eq!(out.data["items"][0]["packages"][0]["fixed"], "9.8");
    }
}
