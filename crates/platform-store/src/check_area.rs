//! What a compliance check is about, from its rule ID (step 5c ruling 3),
//! and which agent collector its facts come from (user decision 1). Both
//! maps match the first listed prefix (none overlap); `console_check_area(text)`
//! (schema 63) is the SQL twin of [`check_area`], kept equal by a test
//! over every baseline and hardening rule ID.

/// Rule-ID prefix → area, most specific first.
const AREAS: [(&str, &str); 13] = [
    ("port.", "Network exposure"),
    ("package.", "Packages"),
    ("harden.ssh.", "SSH"),
    ("harden.net.", "Network"),
    ("harden.kernel.", "Kernel"),
    ("harden.modules.", "Kernel"),
    ("harden.files.", "Files"),
    ("harden.fs.", "Files"),
    ("harden.accounts.", "Accounts"),
    ("harden.login.", "Accounts"),
    ("harden.lsm.", "Security modules"),
    ("harden.services.", "Services"),
    ("test.", "Tests"),
];

/// Rule-ID prefix → the collector name the agent reports in its heartbeat
/// (`health.last_scan.collectors`). Source: openvibes-agent
/// `crates/openvibes-agent/src/scan.rs` (`processes`, `ports`, `packages`,
/// and `hardening` for the root-facts helper, which also provides the
/// `service.*`, `kernel.*` and `lsm.*` facts of `harden.*` rules); the
/// facts each rule reads were checked against openvibes-rules
/// `baseline/rules.json` and `hardening/linux-l1/rules.json` (`port.*` read
/// `port.tcp.exposed`, `package.*` `package.names`, `test.*`
/// `process.names`).
const COLLECTORS: [(&str, &str); 4] = [
    ("port.", "ports"),
    ("package.", "packages"),
    ("harden.", "hardening"),
    ("test.", "processes"),
];

/// The check's area: "Network exposure", "Packages", "SSH", "Network",
/// "Kernel", "Files", "Accounts", "Security modules", "Services", "Tests"
/// or "Other".
#[must_use]
pub fn check_area(rule_id: &str) -> &'static str {
    AREAS
        .iter()
        .find(|(prefix, _)| rule_id.starts_with(prefix))
        .map_or("Other", |(_, area)| area)
}

/// The collector the check's facts come from; `None` for a rule ID with
/// no known prefix (a site rule), whose collector is not checked.
#[must_use]
pub fn check_collector(rule_id: &str) -> Option<&'static str> {
    COLLECTORS
        .iter()
        .find(|(prefix, _)| rule_id.starts_with(prefix))
        .map(|(_, name)| *name)
}

/// [`check_collector`] as an SQL expression over the text expression
/// `rule_id` (NULL for no known prefix). Fixed strings only.
pub(crate) fn collector_sql(rule_id: &str) -> String {
    let arms: String = COLLECTORS
        .iter()
        .map(|(prefix, name)| format!(" WHEN starts_with({rule_id}, '{prefix}') THEN '{name}'"))
        .collect();
    format!("(CASE{arms} END)")
}
