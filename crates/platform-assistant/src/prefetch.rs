//! Lookups the platform runs before the model's first turn (decision
//! 2026-10-10: get the most out of a small model). A small model often skips
//! the obvious lookup or copies an ID wrongly, so code finds them in the
//! question and the model starts from their results:
//!
//! - the object the user attached ("About advisory ID (label): …", as the
//!   console sends it);
//! - advisory and CVE IDs written in the question;
//! - a broad "what to fix first" question: the fleet overview, whose
//!   advisories are already in fix-first order.
//!
//! The lookups run like the model's own (scope, size limits, citations), so
//! nothing here widens what an answer can contain.

use serde_json::{Value, json};

/// Most lookups run before the model's first turn.
pub const MAX_PREFETCH: usize = 2;

/// Words of a broad prioritising question.
const PRIORITY: [&str; 6] = [
    "fix first",
    "most critical",
    "most important",
    "most urgent",
    "priorit",
    "start with",
];

/// The lookups to run first for `question`: `(name, arguments)`, at most
/// [`MAX_PREFETCH`], without duplicates.
#[must_use]
pub fn plan(question: &str) -> Vec<(&'static str, Value)> {
    let mut out: Vec<(&'static str, Value)> = Vec::new();
    let mut add = |name: &'static str, arguments: Value| {
        if out.len() < MAX_PREFETCH && !out.iter().any(|(n, a)| *n == name && *a == arguments) {
            out.push((name, arguments));
        }
    };
    let (context, rest) = context(question);
    if let Some((kind, id)) = context {
        match kind {
            "advisory" => add("vulnerability_hosts", json!({ "id": id })),
            "agent" => add("agent_summary", json!({ "agent": id })),
            "finding" => {
                if let Some((set, rule)) = id.split_once('/') {
                    add(
                        "finding_endpoints",
                        json!({ "rule_set": set, "rule": rule }),
                    );
                }
            }
            _ => {}
        }
    }
    for id in ids(rest) {
        add("vulnerability_hosts", json!({ "id": id }));
    }
    let lower = rest.to_lowercase();
    if PRIORITY.iter().any(|w| lower.contains(w)) {
        add("fleet_overview", json!({}));
    }
    out
}

/// The console's leading note `About KIND ID (LABEL): ` and the question
/// after it.
fn context(question: &str) -> (Option<(&str, &str)>, &str) {
    let Some(rest) = question.strip_prefix("About ") else {
        return (None, question);
    };
    let mut words = rest.splitn(3, ' ');
    let (Some(kind), Some(id), Some(tail)) = (words.next(), words.next(), words.next()) else {
        return (None, question);
    };
    if !matches!(kind, "advisory" | "agent" | "finding") || !tail.starts_with('(') {
        return (None, question);
    }
    // The label may hold "): " itself; the question follows the last one.
    match tail.rfind("): ") {
        Some(end) => (Some((kind, id)), &tail[end + 3..]),
        None => (None, question),
    }
}

/// Advisory and CVE IDs in `text`: an uppercase prefix, a dash, then a year
/// and more, e.g. CVE-2026-1234, FEDORA-2026-6261b26f4e, ALSA-2026:1234,
/// DSA-5912-1, USN-7101-1.
fn ids(text: &str) -> Vec<&str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == ':'))
        .map(|w| w.trim_end_matches([':', '-']))
        .filter(|w| is_id(w))
        .collect()
}

fn is_id(word: &str) -> bool {
    let Some((prefix, rest)) = word.split_once('-') else {
        return false;
    };
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    (2..=8).contains(&prefix.len())
        && prefix.chars().all(|c| c.is_ascii_uppercase())
        && digits >= 3
        && word.len() <= 64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_attached_advisory_and_a_named_one_are_looked_up() {
        let q = "About advisory FEDORA-2026-bcdfa4c7db (chromium-154.0): Isn't FEDORA-2026-6261b26f4e critical?";
        assert_eq!(
            plan(q),
            [
                (
                    "vulnerability_hosts",
                    json!({ "id": "FEDORA-2026-bcdfa4c7db" })
                ),
                (
                    "vulnerability_hosts",
                    json!({ "id": "FEDORA-2026-6261b26f4e" })
                ),
            ]
        );
    }

    #[test]
    fn a_fix_first_question_gets_the_overview() {
        assert_eq!(
            plan("What should I fix first?"),
            [("fleet_overview", json!({}))]
        );
        assert_eq!(
            plan("How do I prioritise?"),
            [("fleet_overview", json!({}))]
        );
        assert!(plan("Which hosts are offline?").is_empty());
    }

    #[test]
    fn hosts_and_findings_attached_are_looked_up() {
        assert_eq!(
            plan("About agent agent.1 (web-01): what is wrong?"),
            [("agent_summary", json!({ "agent": "agent.1" }))]
        );
        assert_eq!(
            plan(
                "About finding baseline/port.ssh.exposed (port.ssh.exposed SSH (port 22): open): fix?"
            ),
            [(
                "finding_endpoints",
                json!({ "rule_set": "baseline", "rule": "port.ssh.exposed" })
            )]
        );
    }

    #[test]
    fn ids_of_every_distribution_and_cves_are_found_once() {
        assert_eq!(
            ids("CVE-2026-1234, ALSA-2026:1234 and DSA-5912-1 (USN-7101-1). CVE-2026-1234?"),
            [
                "CVE-2026-1234",
                "ALSA-2026:1234",
                "DSA-5912-1",
                "USN-7101-1",
                "CVE-2026-1234"
            ]
        );
        assert_eq!(
            plan("CVE-2026-1234 or CVE-2026-1234?").len(),
            1,
            "no duplicates"
        );
        assert!(ids("Is SSH-2 or TLS-1.3 or x-2026 on web-01?").is_empty());
    }

    #[test]
    fn at_most_two_and_a_bare_about_is_a_question() {
        assert_eq!(
            plan("Fix first: CVE-2026-0001, CVE-2026-0002, CVE-2026-0003").len(),
            MAX_PREFETCH
        );
        assert_eq!(
            plan("About my servers: what should I fix first?"),
            [("fleet_overview", json!({}))]
        );
    }
}
