//! The Database and Health screens' state and keys (admin TUI spec §5).
//! Database work runs the admin CLI as `openvibes-admin` through the host,
//! so it keeps its peer login, schema checks and audit log.

use std::path::Path;

use chrono::{DateTime, Utc};
use platform_host::{Database, DiskUse, Host, HostError, ServiceStatus};

use super::app::{App, Key, Tab};
use crate::setup::pki::RENEW_DAYS;

/// Disk use from which Health reports a problem.
const DISK_FULL_PERCENT: u8 = 90;
/// A published rule bundle expiring sooner than this is a problem
/// (baseline rules spec §8).
const RULES_WARN_DAYS: i64 = 90;
/// Days before a site rule set expires that Health warns (board #107).
const SITE_WARN_DAYS: i64 = 30;

/// Both screens' state.
#[derive(Default)]
pub struct DatabaseScreen {
    /// `status` output, or why it could not be read.
    pub status: Vec<String>,
    /// A command waiting for y/n.
    pub confirm: Option<Database>,
    /// Health's lines, problems first.
    pub health: Vec<Check>,
}

/// One Health line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Check {
    pub problem: bool,
    pub text: String,
}

fn check(problem: bool, text: String) -> Check {
    Check { problem, text }
}

/// Health's lines from what the host reported, problems first.
/// A problem per certificate that misses one of this host's addresses,
/// e.g. after DHCP gave it a new one (board #71): the console no longer
/// opens by that IP without a warning until Repair reissues it.
pub fn uncovered(
    certificates: &[(&str, Result<String, HostError>)],
    addresses: &[String],
) -> Vec<Check> {
    certificates
        .iter()
        .filter_map(|(path, pem)| {
            let names = platform_pki::subject_alt_names(pem.as_ref().ok()?).ok()?;
            let missing: Vec<&str> = addresses
                .iter()
                .map(String::as_str)
                .filter(|address| !names.iter().any(|name| name == address))
                .collect();
            (!missing.is_empty()).then(|| {
                check(
                    true,
                    format!(
                        "{path}: does not cover {} (this host): press r on Setup to repair",
                        missing.join(", ")
                    ),
                )
            })
        })
        .collect()
}

pub fn checks(
    services: &[ServiceStatus],
    certificates: &[(&str, Result<String, HostError>)],
    feeds: Result<String, HostError>,
    disk: Result<Vec<DiskUse>, HostError>,
    rules: Result<String, HostError>,
    now: DateTime<Utc>,
) -> Vec<Check> {
    let mut checks = Vec::new();
    for status in services.iter().filter(|status| status.installed) {
        let ready = match status.ready {
            Some(true) => ", ready",
            Some(false) => ", not ready",
            None => "",
        };
        checks.push(check(
            status.active != "active" || status.ready == Some(false),
            format!("{}: {}{ready}", status.unit.label(), status.active),
        ));
    }
    for (path, pem) in certificates {
        let expiry = pem
            .as_ref()
            .map_err(ToString::to_string)
            .and_then(|pem| platform_pki::not_after(pem).map_err(|error| format!("{error:?}")));
        checks.push(match expiry {
            Ok(expires) => {
                let days = (expires - now).num_days();
                let date = expires.format("%Y-%m-%d");
                if expires <= now {
                    check(true, format!("{path}: expired on {date}"))
                } else {
                    check(
                        days < RENEW_DAYS,
                        format!("{path}: expires in {days} days ({date})"),
                    )
                }
            }
            Err(error) => check(true, format!("{path}: {error}")),
        });
    }
    match feeds {
        Ok(out) => {
            // `feeds status` ends a failing feed's line with ` error: TEXT`
            // (vulns.rs, `FeedsCommand::Status`).
            let errors: Vec<&str> = out.lines().filter(|l| l.contains(" error: ")).collect();
            if errors.is_empty() {
                let feeds = out.lines().filter(|l| *l != "no feeds yet").count();
                checks.push(check(false, format!("feeds: {feeds}, no errors")));
            }
            checks.extend(
                errors
                    .iter()
                    .map(|line| check(true, format!("feed {line}"))),
            );
        }
        Err(error) => checks.push(check(true, format!("database: {error}"))),
    }
    match disk {
        Ok(disks) => checks.extend(disks.iter().map(|disk| {
            check(
                disk.used_percent >= DISK_FULL_PERCENT,
                format!(
                    "{}: {}% used, {} free",
                    disk.path, disk.used_percent, disk.available
                ),
            )
        })),
        Err(error) => checks.push(check(true, format!("disk use: {error}"))),
    }
    match rules {
        Ok(out) => {
            let sets: Vec<Check> = out.lines().filter_map(|line| rule_set(line, now)).collect();
            // Board #111: distribution running with nothing to serve leaves
            // every agent without rules, silently.
            let distribution = services
                .iter()
                .any(|status| status.installed && status.unit == platform_host::Unit::Distribution);
            if distribution && sets.is_empty() {
                checks.push(check(
                    true,
                    "no rule set published: agents get no rules; press r on Setup to repair, \
                     or publish one (rules publish)"
                        .into(),
                ));
            }
            checks.extend(sets);
        }
        Err(error) => checks.push(check(true, format!("rule sets: {error}"))),
    }
    // Stable: within problems and within the rest, the order above stays.
    checks.sort_by_key(|check| !check.problem);
    checks
}

/// Health's line about the assistant's tuning (`tune.json`), when a bundled
/// model is installed.
pub fn tune_check(model_installed: bool, tune_json: Option<String>) -> Option<Check> {
    match tune_json {
        Some(text) => {
            let v: serde_json::Value = serde_json::from_str(&text).ok()?;
            if let Some(line) = v["summary"].as_str() {
                return Some(check(false, line.to_owned()));
            }
            let line = crate::tune::summary(
                &format!("CPU ({} threads)", v["threads"].as_u64()?),
                v["model"].as_str()?,
                v["seconds_per_call"].as_f64()?,
                None,
            );
            Some(check(false, line))
        }
        None => model_installed.then(|| {
            check(
                false,
                "assistant: not tuned for this host; turn the assistant on in Setup again to tune it"
                    .into(),
            )
        }),
    }
}

/// Health's line for [`audit_off`](crate::setup::audit_off), when it applies.
pub fn audit_check(rules: &str) -> Option<Check> {
    crate::setup::audit_off(rules).then(|| {
        check(
            true,
            format!(
                "threat alarms can't fire: {} has `-a task,never` (syscall auditing off). \
                 Comment that line out in /etc/audit/rules.d/audit.rules and run `augenrules --load`: \
                 new logins and restarted services are watched; a reboot covers everything",
                crate::setup::AUDIT_RULES
            ),
        )
    })
}

/// One `rules list` line (`SET vN keys K expires TIME [flags]`, rules.rs):
/// the current bundle's expiry. Sets that are retired or have no bundle
/// are left out.
fn rule_set(line: &str, now: DateTime<Utc>) -> Option<Check> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let [set, version, "keys", _, "expires", time, flags @ ..] = fields.as_slice() else {
        return None;
    };
    if *version == "none" || flags.contains(&"retired") {
        return None;
    }
    let name = format!("rule set {set} {version}");
    let Ok(expires) = DateTime::parse_from_rfc3339(time) else {
        return Some(check(true, format!("{name}: no readable expiry ({time})")));
    };
    let expires = expires.with_timezone(&Utc);
    let date = expires.format("%Y-%m-%d");
    // The site's own sets are renewed by publishing again (board #107);
    // the signer re-signs only with a live password, so warn a month ahead.
    let (fix, warn_days) = if *set == "site" || *set == "site-alarms" {
        ("publish again in the console to renew", SITE_WARN_DAYS)
    } else {
        (
            "install the newer rules package and run Repair, or publish a newer bundle",
            RULES_WARN_DAYS,
        )
    };
    let days = (expires - now).num_days();
    Some(if expires <= now {
        check(true, format!("{name}: expired on {date}; {fix}"))
    } else if days < warn_days {
        check(
            true,
            format!("{name}: expires in {days} days ({date}); {fix}"),
        )
    } else {
        check(false, format!("{name}: expires in {days} days ({date})"))
    })
}

/// Health's lines about the rule signer (board #107): its version state,
/// recent refusals, and the site key agents must trust.
pub fn signer_checks(files: &platform_host::SignerFiles) -> Vec<Check> {
    let mut checks = Vec::new();
    match &files.status {
        Err(error) => checks.push(check(true, format!("rule signer: {error}"))),
        Ok(text) => match serde_json::from_str::<serde_json::Value>(text) {
            Err(_) => checks.push(check(
                true,
                "rule signer: status.json is not readable JSON".into(),
            )),
            Ok(status) => {
                if status["version_state"] != true {
                    checks.push(check(
                        true,
                        "rule signer: no version state, so it signs nothing: run Repair".into(),
                    ));
                }
                let refusals = status["refusals_last_day"]
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                let total: u64 = refusals
                    .values()
                    .filter_map(serde_json::Value::as_u64)
                    .sum();
                let publishes = status["publishes_last_hour"].as_u64().unwrap_or(0);
                if total == 0 {
                    checks.push(check(
                        false,
                        format!("rule signer: {publishes} publishes in the last hour, none refused today"),
                    ));
                } else {
                    let codes: Vec<String> = refusals
                        .iter()
                        .map(|(code, n)| format!("{code} {}", n.as_u64().unwrap_or(0)))
                        .collect();
                    // Rate, lockouts and failures need a look; a wrong
                    // password now and then doesn't.
                    let serious = ["rate", "throttled", "unavailable", "version_state"]
                        .iter()
                        .any(|code| {
                            refusals.get(*code).and_then(serde_json::Value::as_u64) > Some(0)
                        });
                    checks.push(check(
                        serious,
                        format!(
                            "rule signer: {total} publishes refused in the last day ({})",
                            codes.join(", ")
                        ),
                    ));
                }
            }
        },
    }
    if let Some(key) = files
        .trust
        .as_deref()
        .and_then(|trust| trust.lines().next())
        .and_then(|line| line.split_whitespace().nth(2))
    {
        let short: String = key.chars().take(8).collect();
        checks.push(check(
            false,
            format!(
                "site key {short}…: agents need its lines from `agent command`; \
                 after a reinstall the key is new, and agents trusting an old site key refuse the site rules"
            ),
        ));
    }
    checks
}

impl<H: Host> App<H> {
    /// Opens the Database screen.
    pub fn open_database(&mut self) {
        self.tab = Tab::Database;
        self.message = None;
        self.load_database();
    }

    fn load_database(&mut self) {
        self.database.status = match self.host.database(Database::Status) {
            Ok(out) => out.lines().map(str::to_owned).collect(),
            Err(error) => vec![error.to_string()],
        };
    }

    /// m/n ask to migrate / run maintenance, y answers, R reloads, Tab
    /// opens Health, q quits.
    pub(super) fn database_key(&mut self, key: Key) {
        if let Some(command) = self.database.confirm.take() {
            if key == Key::Char('y') {
                self.message = Some(match self.host.database(command) {
                    Ok(out) => out.trim().replace('\n', "; "),
                    Err(error) => error.to_string(),
                });
                self.load_database();
            }
            return;
        }
        match key {
            Key::Char('m') => self.database.confirm = Some(Database::Migrate),
            Key::Char('n') => self.database.confirm = Some(Database::Maintenance),
            Key::Char('R') => {
                self.message = None;
                self.load_database();
            }
            _ => {}
        }
    }

    /// Reloads the health checks (Status shows them; a refresh of the
    /// units comes with it).
    pub(super) fn load_health(&mut self) {
        self.refresh();
        self.database.health = health_checks(&self.host);
    }
}

/// Every health check (certificates, disk, feeds, signer, audit, tuning),
/// problems first. The unit lines are built by Status, not here. Slow on a
/// real host: `run` calls it on another thread.
pub fn health_checks<H: Host>(host: &H) -> Vec<Check> {
    let certificates = host.certificates();
    let mut health = checks(
        &[],
        &certificates,
        host.database(Database::FeedsStatus),
        host.disk(),
        host.database(Database::RulesList),
        Utc::now(),
    );
    health.extend(uncovered(&certificates, &host.addresses()));
    if let Some(files) = host.signer() {
        health.extend(signer_checks(&files));
    }
    // Readable as root only; as another user the line is left out. Only
    // an agent reading kernel audit (its exec rule in rules.d) cares: an
    // eBPF host's agent does not.
    if Path::new(crate::setup::AGENT_AUDIT_RULE).exists()
        && let Ok(rules) = std::fs::read_to_string(crate::setup::AUDIT_RULES)
    {
        health.extend(audit_check(&rules));
    }
    health.extend(tune_check(
        Path::new("/var/lib/openvibes-llm/model.conf").exists(),
        std::fs::read_to_string("/var/lib/openvibes-llm/tune.json").ok(),
    ));
    health.sort_by_key(|check| !check.problem);
    health
}
