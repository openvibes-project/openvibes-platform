//! The printed agent install line.

const DEFAULTS: (u16, u16) = (18423, 18424);

#[test]
fn chosen_agent_ports_travel_only_when_not_the_defaults() {
    let rules = Some("baseline,openvibes-1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let line = super::agent_install_command("h.example", (18500, 18424), "T", "AB:CD", rules, None);
    assert!(line.contains(" --platform h.example:18500 "), "{line}");
    assert!(!line.contains("--distribution-port"), "{line}");
    let line = super::agent_install_command("h.example", (18423, 18501), "T", "AB:CD", rules, None);
    assert!(line.contains(" --platform h.example "), "{line}");
    assert!(line.ends_with(" --distribution-port 18501"), "{line}");
    // Without rules the agent never asks distribution.
    let line = super::agent_install_command("h.example", (18423, 18501), "T", "AB:CD", None, None);
    assert!(!line.contains("--distribution-port"), "{line}");
}

#[test]
fn the_agent_install_command_is_one_line() {
    assert_eq!(
        super::agent_install_command("h.example", DEFAULTS, "T", "AB:CD", None, None),
        "curl -fsSL https://openvibes-project.github.io/install.sh | sudo sh -s -- \
         --agent --platform h.example --token T --ca-sha256 AB:CD"
    );
}

#[test]
fn rules_ride_along_only_when_the_served_bundle_uses_that_key() {
    const K: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const OTHER: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let line = format!("baseline openvibes-1 {K}\n");
    let served = |set: &str, issuer: &str, key: &str| super::Served {
        set: set.into(),
        issuer: issuer.into(),
        key: key.into(),
    };
    assert_eq!(
        super::published_rules_arg(&line, &[served("baseline", "openvibes-1", K)]).as_deref(),
        Some(format!("baseline,openvibes-1,{K}").as_str())
    );
    // Not published, another set, another signer, or another key for
    // the same issuer: the agent could not verify what is served.
    for others in [
        vec![],
        vec![served("other", "openvibes-1", K)],
        vec![served("baseline", "org.rules", K)],
        vec![served("baseline", "openvibes-1", OTHER)],
    ] {
        assert_eq!(
            super::published_rules_arg(&line, &others),
            None,
            "{others:?}"
        );
    }
}

#[test]
fn the_baseline_trust_line_rides_along() {
    let key = "baseline openvibes-1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
    let rules = super::rules_arg(key);
    assert_eq!(
        rules.as_deref(),
        Some("baseline,openvibes-1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    );
    assert!(
        super::agent_install_command("h.example", DEFAULTS, "T", "AB:CD", rules.as_deref(), None)
            .ends_with(" --rules baseline,openvibes-1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    );
    // Anything that could break the shell line or the installer's check
    // is left out rather than quoted.
    for bad in [
        "baseline openvibes-1",
        "baseline openvibes-1 A B",
        "base line x y",
        "b;rm x A",
    ] {
        assert_eq!(super::rules_arg(bad), None, "{bad}");
    }
}

/// Rules v2: the install line also names the alarm rules, but only with
/// --rules (they share the distribution URL); the installer gates them on
/// a P14 agent.
#[test]
fn the_alarm_rules_ride_along_with_the_rules() {
    let rules = Some("baseline,openvibes-1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let alarms = Some("baseline-alarms,openvibes-1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let line = super::agent_install_command("h.example", DEFAULTS, "T", "AB:CD", rules, alarms);
    assert!(
        line.ends_with(
            " --alarm-rules baseline-alarms,openvibes-1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ),
        "{line}"
    );
    let line = super::agent_install_command("h.example", DEFAULTS, "T", "AB:CD", None, alarms);
    assert!(!line.contains("--alarm-rules"), "{line}");
}
