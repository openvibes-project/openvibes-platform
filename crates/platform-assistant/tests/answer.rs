//! Output cleaning (spec §6): model text can never become markup, a link, a
//! hidden instruction, or a citation of an object the user was not shown.

use std::collections::BTreeSet;

use platform_assistant::{Citation, Segment, plain_text, sanitize};

fn agent(id: &str) -> Citation {
    Citation::Agent(id.into())
}

fn allowed() -> BTreeSet<Citation> {
    [
        agent("agent.a"),
        Citation::Finding {
            rule_set: "baseline".into(),
            rule: "ssh.exposed".into(),
        },
        Citation::Finding {
            rule_set: String::new(),
            rule: "legacy.rule".into(),
        },
        Citation::Advisory("FEDORA-2026-1".into()),
    ]
    .into()
}

fn text(piece: &str) -> Segment {
    Segment::Text(piece.into())
}

#[test]
fn only_allowed_citations_become_links() {
    let segments = sanitize(
        "Host [agent:agent.a] has [finding:baseline/ssh.exposed] and [advisory:FEDORA-2026-1]; \
         [agent:agent.evil] and [finding:~unknown/legacy.rule] and [note] too.",
        &allowed(),
    );
    assert_eq!(
        segments,
        vec![
            text("Host "),
            Segment::Cite(agent("agent.a")),
            text(" has "),
            Segment::Cite(Citation::Finding {
                rule_set: "baseline".into(),
                rule: "ssh.exposed".into()
            }),
            text(" and "),
            Segment::Cite(Citation::Advisory("FEDORA-2026-1".into())),
            text("; [agent:agent.evil] and "),
            Segment::Cite(Citation::Finding {
                rule_set: String::new(),
                rule: "legacy.rule".into()
            }),
            text(" and [note] too."),
        ]
    );
}

#[test]
fn malformed_citations_stay_text() {
    for hostile in [
        "[agent:]",
        "[agent:agent.a",
        "[agent:agent a]",
        "[agent:agent.a/../x]",
        "[finding:baseline]",
        "[finding:/ssh.exposed]",
        "[AGENT:agent.a]",
        "[agent:agent.a<script>]",
        "[[agent:agent.a]]",
    ] {
        let segments = sanitize(hostile, &allowed());
        let cites = segments
            .iter()
            .filter(|s| matches!(s, Segment::Cite(_)))
            .count();
        let expected = usize::from(hostile == "[[agent:agent.a]]");
        assert_eq!(cites, expected, "{hostile}");
        assert!(
            plain_text(&segments).contains("agent") || plain_text(&segments).contains("finding")
        );
    }
}

#[test]
fn links_markup_and_hidden_characters_are_made_inert() {
    let segments = sanitize(
        "See https://evil.example/x and ![img](http://evil.example/p.png) <b>bold</b>\u{202E}gnp.exe\u{200B} \
         and\u{0007} \u{1b}[31mred\ttab\nline",
        &allowed(),
    );
    let shown = plain_text(&segments);
    assert!(!shown.contains("://"), "{shown}");
    assert!(shown.contains("https[:]//evil.example/x"));
    assert!(shown.contains("http[:]//evil.example/p.png"));
    // Markup is left as literal text for a plain-text renderer.
    assert!(shown.contains("<b>bold</b>"));
    for hidden in ['\u{202E}', '\u{200B}', '\u{0007}', '\u{1b}'] {
        assert!(!shown.contains(hidden), "{hidden:?}");
    }
    assert!(shown.contains("red\ttab\nline"));
}

#[test]
fn answers_are_bounded_and_trimmed() {
    let long = "x".repeat(20_000);
    let shown = plain_text(&sanitize(&long, &allowed()));
    assert_eq!(shown.len(), 8_000);
    assert!(sanitize("   \n\t ", &allowed()).is_empty());
    assert_eq!(sanitize("answer  \n", &allowed()), vec![text("answer")]);
}

#[test]
fn citations_round_trip() {
    for citation in allowed() {
        assert_eq!(
            Citation::parse(&citation.to_string()),
            Some(citation.clone())
        );
    }
    assert_eq!(
        Citation::Finding {
            rule_set: String::new(),
            rule: "r".into()
        }
        .to_string(),
        "[finding:~unknown/r]"
    );
}
