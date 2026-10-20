//! The detail a step adds to its journal line (#292).

/// Longest detail kept on a journal line.
const MAX: usize = 300;

/// `": DETAIL"` for the verbs that print `STATE<TAB>DETAIL` (a step), cut to
/// `MAX` characters; empty for any other verb or an empty detail. A detail
/// can hold a secret (the console step prints the generated admin password,
/// the Ready step an enrollment hint), and the journal is readable by many:
/// the console step's detail is never logged, and any detail naming a
/// password or token is withheld.
pub fn step_suffix(action: &str, target: &str, stdout: &str) -> String {
    const WITHHELD: &str = ": (detail withheld)";
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
    let lower = detail.to_ascii_lowercase();
    let console = action == "setup-step" && target.split(' ').next() == Some("console");
    if console || lower.contains("password") || lower.contains("token") {
        return WITHHELD.into();
    }
    format!(": {}", &detail[..end])
}
