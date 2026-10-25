use super::{
    ItemKind, case_severity_of, default_severity,
    items::{Parsed, parse_ref},
    list::case_number,
    note_ok, title_ok,
};

#[test]
fn refs_are_checked_against_the_shape_the_panels_write() {
    let agent = "agent.00000000-0000-4000-8000-000000000001";
    assert_eq!(parse_ref(ItemKind::Alarm, "42"), Some(Parsed::Alarm(42)));
    for bad in ["", "0", "-1", "042", "4 2", "1e3", "99999999999999999999"] {
        assert_eq!(parse_ref(ItemKind::Alarm, bad), None, "{bad:?}");
    }
    let finding = format!("{agent}/baseline/ssh-root-login");
    assert_eq!(
        parse_ref(ItemKind::Finding, &finding),
        Some(Parsed::Finding(agent, "baseline", "ssh-root-login"))
    );
    // A finding from before rule sets has an empty rule set.
    assert!(parse_ref(ItemKind::Finding, &format!("{agent}//old-rule")).is_some());
    for bad in [
        agent.to_owned(),
        format!("{agent}/baseline"),
        format!("{agent}/baseline/rule/extra"),
        format!("{agent}/baseline/"),
        "/baseline/rule".to_owned(),
        format!("{agent}/base line/rule"),
    ] {
        assert_eq!(parse_ref(ItemKind::Finding, &bad), None, "{bad:?}");
    }
    assert_eq!(
        parse_ref(ItemKind::Vulnerability, &format!("{agent}/RHSA-2026:1234")),
        Some(Parsed::Vulnerability(agent, "RHSA-2026:1234"))
    );
    assert_eq!(parse_ref(ItemKind::Vulnerability, agent), None);
    assert_eq!(parse_ref(ItemKind::Host, agent), Some(Parsed::Host(agent)));
    assert_eq!(parse_ref(ItemKind::Host, "a/b"), None);
    // A package name may itself contain a slash.
    assert_eq!(
        parse_ref(ItemKind::Software, "npm/@scope/pkg"),
        Some(Parsed::Software("npm", "@scope/pkg"))
    );
    assert_eq!(parse_ref(ItemKind::Software, "rpm"), None);
    assert_eq!(parse_ref(ItemKind::Software, "rpm/"), None);
}

#[test]
fn only_alarms_findings_and_vulnerabilities_are_exclusive() {
    for (name, exclusive) in [
        ("alarm", true),
        ("compliance_finding", true),
        ("vulnerability", true),
        ("host", false),
        ("software", false),
    ] {
        assert_eq!(ItemKind::parse(name).unwrap().exclusive(), exclusive);
    }
    assert_eq!(ItemKind::parse("port"), None);
}

#[test]
fn the_default_severity_is_the_highest_item_severity() {
    assert_eq!(case_severity_of("important"), Some("high"));
    assert_eq!(case_severity_of("moderate"), Some("medium"));
    assert_eq!(case_severity_of("info"), Some("low"));
    assert_eq!(case_severity_of("weird"), None);
    assert_eq!(
        default_severity([Some("low"), None, Some("important"), Some("moderate")]),
        "high"
    );
    assert_eq!(
        default_severity([Some("critical"), Some("high")]),
        "critical"
    );
    assert_eq!(default_severity([None, Some("weird")]), "medium");
    assert_eq!(default_severity([]), "medium");
}

#[test]
fn titles_and_notes_are_bounded_plain_text() {
    assert!(title_ok("SSH on web-01"));
    assert!(!title_ok(""));
    assert!(!title_ok(" padded "));
    assert!(!title_ok("tab\there"));
    assert!(title_ok(&"é".repeat(120)));
    assert!(!title_ok(&"é".repeat(121)));
    assert!(note_ok("line one\nline two\twith a tab"));
    assert!(!note_ok("   "));
    assert!(!note_ok("bell\u{7}"));
    assert!(note_ok(&"n".repeat(4000)));
    assert!(!note_ok(&"n".repeat(4001)));
}

#[test]
fn case_numbers_are_found_in_search_text() {
    assert_eq!(case_number("C-104"), Some(104));
    assert_eq!(case_number("c-7"), Some(7));
    assert_eq!(case_number("c104"), Some(104));
    assert_eq!(case_number("104"), Some(104));
    assert_eq!(case_number("ssh"), None);
    assert_eq!(case_number("C-0"), None);
    assert_eq!(case_number("C--1"), None);
}
