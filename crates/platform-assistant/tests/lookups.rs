//! Lookup requests from the model are parsed strictly (spec §5), and results
//! stay bounded with citations taken only from platform-written keys.

use platform_assistant::{
    Citation, Lookup, LookupError, LookupOutput,
    lookups::{NAMES, specs},
};
use serde_json::json;

#[test]
fn specs_are_strict_and_match_the_names() {
    let specs = specs();
    let names: Vec<_> = specs.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, NAMES);
    for spec in &specs {
        assert_eq!(spec.parameters["type"], "object", "{}", spec.name);
        assert_eq!(
            spec.parameters["additionalProperties"], false,
            "{}",
            spec.name
        );
    }
}

#[test]
fn valid_requests_parse_with_defaults() {
    assert_eq!(
        Lookup::parse("search_findings", "").unwrap(),
        Lookup::SearchFindings {
            text: None,
            min_severity: None,
            rule_set: None,
            window_hours: 24
        }
    );
    assert_eq!(
        Lookup::parse(
            "search_findings",
            r#"{"text":" ssh ","min_severity":"HIGH","rule_set":"baseline","window_hours":72}"#
        )
        .unwrap(),
        Lookup::SearchFindings {
            text: Some("ssh".into()),
            min_severity: Some("high"),
            rule_set: Some("baseline".into()),
            window_hours: 72
        }
    );
    assert_eq!(
        Lookup::parse(
            "finding_endpoints",
            r#"{"rule_set":"~unknown","rule":"legacy.rule"}"#
        )
        .unwrap(),
        Lookup::FindingEndpoints {
            rule_set: String::new(),
            rule: "legacy.rule".into(),
            window_hours: 24
        }
    );
    assert_eq!(
        Lookup::parse(
            "host_vulnerabilities",
            r#"{"agent":"web-01","min_severity":"important"}"#
        )
        .unwrap(),
        Lookup::HostVulnerabilities {
            agent: "web-01".into(),
            min_severity: Some("important")
        }
    );
    assert!(Lookup::parse("fleet_overview", "{}").is_ok());
    assert!(Lookup::parse("vulnerability_hosts", r#"{"id":"CVE-2026-0001"}"#).is_ok());
    assert!(
        Lookup::parse(
            "rule_description",
            r#"{"rule_set":"baseline","rule":"ssh"}"#
        )
        .is_ok()
    );
    assert!(Lookup::parse("agent_summary", r#"{"agent":"db-02"}"#).is_ok());
}

#[test]
fn anything_else_is_refused() {
    assert_eq!(
        Lookup::parse("drop_table", "{}").unwrap_err(),
        LookupError::Unknown
    );
    assert_eq!(
        Lookup::parse("SEARCH_FINDINGS", "{}").unwrap_err(),
        LookupError::Unknown
    );
    let long = "a".repeat(129);
    for (name, arguments) in [
        (
            "search_findings",
            r#"{"sql":"DROP TABLE agents"}"#.to_owned(),
        ),
        ("search_findings", r#"{"window_hours":0}"#.to_owned()),
        ("search_findings", r#"{"window_hours":721}"#.to_owned()),
        ("search_findings", r#"{"window_hours":"24"}"#.to_owned()),
        ("search_findings", r#"{"min_severity":"urgent"}"#.to_owned()),
        ("search_findings", "[1,2]".to_owned()),
        ("search_findings", "not json".to_owned()),
        ("agent_summary", "{}".to_owned()),
        ("agent_summary", r#"{"agent":"  "}"#.to_owned()),
        ("agent_summary", format!(r#"{{"agent":"{long}"}}"#)),
        ("agent_summary", r#"{"agent":"a\u0000b"}"#.to_owned()),
        ("finding_endpoints", r#"{"rule_set":"baseline"}"#.to_owned()),
        (
            "host_vulnerabilities",
            r#"{"agent":"x","min_severity":"high"}"#.to_owned(),
        ),
    ] {
        assert_eq!(
            Lookup::parse(name, &arguments).unwrap_err(),
            LookupError::InvalidArguments,
            "{name} {arguments}"
        );
    }
}

#[test]
fn audit_arguments_are_the_validated_ones() {
    let lookup = Lookup::parse(
        "search_findings",
        r#"{"text":" ssh ","min_severity":"High"}"#,
    )
    .unwrap();
    assert_eq!(lookup.name(), "search_findings");
    assert_eq!(
        lookup.arguments(),
        json!({ "text": "ssh", "min_severity": "high", "rule_set": null, "window_hours": 24 })
    );
}

fn output(items: usize) -> LookupOutput {
    LookupOutput {
        data: json!({
            "agent": "[agent:agent.summary]",
            "items": (0..items).map(|i| json!({
                "cite": format!("[agent:agent.{i}]"),
                // Host-chosen strings that look like citations never count.
                "hostname": "[agent:agent.evil]",
                "message": "[advisory:FAKE-1]",
                "advisory": "[advisory:FEDORA-2026-1]",
            })).collect::<Vec<_>>(),
            "omitted": 3,
        }),
    }
}

#[test]
fn citations_come_only_from_platform_keys() {
    let citations = output(2).citations();
    assert!(citations.contains(&Citation::Agent("agent.0".into())));
    assert!(citations.contains(&Citation::Agent("agent.summary".into())));
    assert!(citations.contains(&Citation::Advisory("FEDORA-2026-1".into())));
    assert!(!citations.contains(&Citation::Agent("agent.evil".into())));
    assert!(!citations.contains(&Citation::Advisory("FAKE-1".into())));
    assert_eq!(citations.len(), 4);
}

#[test]
fn shrinking_drops_items_and_counts_them() {
    let mut result = output(40);
    let before = result.text().len();
    result.shrink_to(before / 4);
    assert!(result.text().len() <= before / 4);
    let kept = result.data["items"].as_array().unwrap().len();
    assert!(kept < 40);
    assert_eq!(result.data["omitted"], json!(3 + 40 - kept as i64));
    // Citations of dropped items are no longer citable.
    assert!(
        !result
            .citations()
            .contains(&Citation::Agent("agent.39".into()))
    );
    let mut tiny = output(3);
    tiny.shrink_to(1);
    assert_eq!(tiny.data["items"], json!([]));
}
