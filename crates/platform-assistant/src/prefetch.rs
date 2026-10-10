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
/// A mitigation question may run one more: local hosts, reference, search.
pub(crate) const MAX_MITIGATION_PREFETCH: usize = 3;

/// Whether `lower` (lowercase) asks how to mitigate or fix: whole words, so
/// "fixed" (a status) and "prefix" do not count.
fn mitigation(lower: &str) -> bool {
    lower.contains("protect against")
        || lower.split(|c: char| !c.is_alphanumeric()).any(|w| {
            matches!(
                w,
                "fix" | "fixes" | "patch" | "patches" | "patching" | "workaround" | "workarounds"
            ) || w.starts_with("mitigat")
                || w.starts_with("remediat")
        })
}

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
/// [`MAX_PREFETCH`], without duplicates. `internet` is the level the user
/// may use (0 none, 1 reference, 2 reference and search); a question about
/// mitigating one named ID then also gets its reference and a search
/// (`"<ID> mitigation workaround"`, built here), three lookups in all.
#[must_use]
pub fn plan(question: &str, internet: u8) -> Vec<(&'static str, Value)> {
    let mut out: Vec<(&'static str, Value)> = Vec::new();
    let mut max = MAX_PREFETCH;
    let mut add = |name: &'static str, arguments: Value, max: usize| {
        if out.len() < max && !out.iter().any(|(n, a)| *n == name && *a == arguments) {
            out.push((name, arguments));
        }
    };
    let (context, rest) = context(question);
    let mut attached = None;
    if let Some((kind, id)) = context {
        match kind {
            "advisory" => {
                attached = Some(id);
                add("vulnerability_hosts", json!({ "id": id }), max);
            }
            "agent" => add("agent_summary", json!({ "agent": id }), max),
            "finding" => {
                if let Some((set, rule)) = id.split_once('/') {
                    add(
                        "finding_endpoints",
                        json!({ "rule_set": set, "rule": rule }),
                        max,
                    );
                }
            }
            _ => {}
        }
    }
    let named = ids(rest);
    for id in &named {
        add("vulnerability_hosts", json!({ "id": id }), max);
    }
    let lower = rest.to_lowercase();
    if let (Some(id), true) = (
        named.first().copied().or(attached),
        internet > 0 && mitigation(&lower),
    ) {
        max = MAX_MITIGATION_PREFETCH;
        add("reference", json!({ "id": id }), max);
        if internet > 1 {
            add(
                "web_search",
                json!({ "query": format!("{id} mitigation workaround") }),
                max,
            );
        }
    }
    if PRIORITY.iter().any(|w| lower.contains(w)) {
        add("fleet_overview", json!({}), max);
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
            plan(q, 0),
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
            plan("What should I fix first?", 0),
            [("fleet_overview", json!({}))]
        );
        assert_eq!(
            plan("How do I prioritise?", 0),
            [("fleet_overview", json!({}))]
        );
        assert!(plan("Which hosts are offline?", 0).is_empty());
    }

    #[test]
    fn hosts_and_findings_attached_are_looked_up() {
        assert_eq!(
            plan("About agent agent.1 (web-01): what is wrong?", 0),
            [("agent_summary", json!({ "agent": "agent.1" }))]
        );
        assert_eq!(
            plan(
                "About finding baseline/port.ssh.exposed (port.ssh.exposed SSH (port 22): open): fix?",
                0
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
            plan("CVE-2026-1234 or CVE-2026-1234?", 0).len(),
            1,
            "no duplicates"
        );
        assert!(ids("Is SSH-2 or TLS-1.3 or x-2026 on web-01?").is_empty());
    }

    #[test]
    fn at_most_two_and_a_bare_about_is_a_question() {
        assert_eq!(
            plan("Fix first: CVE-2026-0001, CVE-2026-0002, CVE-2026-0003", 0).len(),
            MAX_PREFETCH
        );
        assert_eq!(
            plan("About my servers: what should I fix first?", 0),
            [("fleet_overview", json!({}))]
        );
    }

    #[test]
    fn a_mitigation_question_gathers_local_then_reference_then_search() {
        let q = "How do I mitigate CVE-2024-6387?";
        assert_eq!(
            plan(q, 0),
            [("vulnerability_hosts", json!({ "id": "CVE-2024-6387" }))]
        );
        assert_eq!(
            plan(q, 1),
            [
                ("vulnerability_hosts", json!({ "id": "CVE-2024-6387" })),
                ("reference", json!({ "id": "CVE-2024-6387" })),
            ]
        );
        assert_eq!(
            plan(q, 2),
            [
                ("vulnerability_hosts", json!({ "id": "CVE-2024-6387" })),
                ("reference", json!({ "id": "CVE-2024-6387" })),
                (
                    "web_search",
                    json!({ "query": "CVE-2024-6387 mitigation workaround" })
                ),
            ]
        );
    }

    #[test]
    fn viewers_get_no_internet() {
        // The console passes level 0 for a user without assistant internet access.
        assert!(
            plan("How do I patch CVE-2024-6387?", 0)
                .iter()
                .all(|(n, _)| *n == "vulnerability_hosts")
        );
    }

    #[test]
    fn an_attached_advisory_feeds_the_mitigation_branch() {
        let q = "About advisory FEDORA-2026-bcdfa4c7db (chromium-154.0): How do I fix this?";
        let id = "FEDORA-2026-bcdfa4c7db";
        let local = ("vulnerability_hosts", json!({ "id": id }));
        assert_eq!(plan(q, 0), std::slice::from_ref(&local));
        assert_eq!(
            plan(q, 1),
            [local.clone(), ("reference", json!({ "id": id }))]
        );
        assert_eq!(
            plan(q, 2),
            [
                local,
                ("reference", json!({ "id": id })),
                (
                    "web_search",
                    json!({ "query": format!("{id} mitigation workaround") })
                ),
            ]
        );
        // An ID the question names itself wins over the attached one.
        let q = "About advisory FEDORA-2026-bcdfa4c7db (x): how to patch CVE-2024-6387?";
        assert_eq!(
            plan(q, 1)[2],
            ("reference", json!({ "id": "CVE-2024-6387" }))
        );
    }

    #[test]
    fn mitigation_words_match_whole_words() {
        for q in [
            "Is CVE-2024-6387 fixed on web-01?",
            "Does CVE-2024-6387 affect the prefix tool?",
            "Was CVE-2024-6387 patched?",
        ] {
            assert_eq!(plan(q, 2).len(), 1, "{q}");
        }
        for q in [
            "How do I fix CVE-2024-6387?",
            "patch CVE-2024-6387",
            "Any workaround for CVE-2024-6387?",
            "CVE-2024-6387 mitigation?",
            "Mitigate CVE-2024-6387",
            "How to remediate CVE-2024-6387?",
            "protect against CVE-2024-6387",
        ] {
            assert_eq!(plan(q, 2).len(), 3, "{q}");
        }
    }
}
