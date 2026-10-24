//! What a compliance check is about, from its rule ID (step 5c ruling 3),
//! and which agent collectors its facts come from (user decision 1). Both
//! maps match the first listed prefix; `console_check_area(text)`
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

/// Rule-ID prefix → the collectors whose facts the rule reads, by the
/// names the agent reports in its heartbeat (`health.last_scan.collectors`),
/// first match wins. Source: openvibes-agent `crates/openvibes-agent/src/scan.rs`
/// (`processes`, `ports`, `packages`, and `hardening` for the root-facts
/// helper, which also provides the `service.*`, `sysctl.*`, `kernel.*`,
/// `lsm.*` and file facts of `harden.*` rules); the facts each rule reads
/// were checked against openvibes-rules 65ff4c0 `baseline/rules.json` and
/// `hardening/linux-l1/rules.json` (`port.*` read `port.tcp.exposed`,
/// `package.*` `package.names`, `test.*` `process.names`;
/// `harden.net.ip_forward` also reads `package.names`).
const COLLECTORS: [(&str, &[&str]); 5] = [
    ("harden.net.ip_forward", &["hardening", "packages"]),
    ("port.", &["ports"]),
    ("package.", &["packages"]),
    ("harden.", &["hardening"]),
    ("test.", &["processes"]),
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

/// The collectors the check's facts come from, each of which must have run
/// ok for a host to pass it; `None` for a rule ID with no known prefix (a
/// site rule): then every collector the host reported must be ok.
#[must_use]
pub fn check_collectors(rule_id: &str) -> Option<&'static [&'static str]> {
    COLLECTORS
        .iter()
        .find(|(prefix, _)| rule_id.starts_with(prefix))
        .map(|(_, names)| *names)
}

/// [`check_collectors`] as an SQL condition over the text expression
/// `rule_id`: `colls` (a jsonb array of the collectors that ran ok) holds
/// them all, or, for no known prefix, `all_ok` (every reported collector
/// was ok) holds. Fixed strings only.
pub(crate) fn collectors_ok_sql(rule_id: &str, colls: &str, all_ok: &str) -> String {
    let arms: String = COLLECTORS
        .iter()
        .map(|(prefix, names)| {
            let names = names
                .iter()
                .map(|n| format!("'{n}'"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(" WHEN starts_with({rule_id}, '{prefix}') THEN ({colls}) ?& ARRAY[{names}]")
        })
        .collect();
    format!("(CASE{arms} ELSE {all_ok} END)")
}
