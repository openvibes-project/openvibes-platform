//! The detail a step adds to its journal line (#292).

/// Longest detail kept on a journal line.
const MAX: usize = 300;

/// `": DETAIL"` for the verbs that print `STATE<TAB>DETAIL` (a step), cut to
/// `MAX` characters; empty for any other verb or an empty detail. Step
/// details carry no secrets.
pub fn step_suffix(action: &str, stdout: &str) -> String {
    if !matches!(action, "setup-step" | "update-step" | "remove-step") {
        return String::new();
    }
    let detail = stdout
        .lines()
        .next()
        .and_then(|line| line.split_once('\t'))
        .map_or("", |(_, detail)| detail);
    if detail.is_empty() {
        return String::new();
    }
    let end = detail
        .char_indices()
        .nth(MAX)
        .map_or(detail.len(), |(end, _)| end);
    format!(": {}", &detail[..end])
}
