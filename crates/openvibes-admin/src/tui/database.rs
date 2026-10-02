//! The Database and Health screens' state and keys (admin TUI spec §5).
//! Database work runs the admin CLI as `openvibes-admin` through the host,
//! so it keeps its peer login, schema checks and audit log.

use chrono::{DateTime, Utc};
use platform_host::{Database, DiskUse, Host, HostError, ServiceStatus};

use super::app::{App, Key, Tab};
use crate::setup::pki::RENEW_DAYS;

/// Disk use from which Health reports a problem.
const DISK_FULL_PERCENT: u8 = 90;
/// A published rule bundle expiring sooner than this is a problem
/// (baseline rules spec §8).
const RULES_WARN_DAYS: i64 = 90;

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
        Ok(out) => checks.extend(out.lines().filter_map(|line| rule_set(line, now))),
        Err(error) => checks.push(check(true, format!("rule sets: {error}"))),
    }
    // Stable: within problems and within the rest, the order above stays.
    checks.sort_by_key(|check| !check.problem);
    checks
}

/// Health's line for [`audit_off`](crate::setup::audit_off), when it applies.
pub fn audit_check(rules: &str) -> Option<Check> {
    crate::setup::audit_off(rules).then(|| {
        check(
            true,
            format!(
                "threat alarms can't fire: {} has `-a task,never` (syscall auditing off). \
                 Comment that line out in /etc/audit/rules.d/, run `augenrules --load`, \
                 then reboot (or restart services) so running programs are watched too",
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
    let fix = "install the newer rules package and run Repair, or publish a newer bundle";
    let days = (expires - now).num_days();
    Some(if expires <= now {
        check(true, format!("{name}: expired on {date}; {fix}"))
    } else if days < RULES_WARN_DAYS {
        check(
            true,
            format!("{name}: expires in {days} days ({date}); {fix}"),
        )
    } else {
        check(false, format!("{name}: expires in {days} days ({date})"))
    })
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
            Key::Tab => self.open_health(),
            Key::BackTab => self.open(Tab::Configuration),
            Key::Char('q') => self.quit = true,
            _ => {}
        }
    }

    pub(super) fn open_health(&mut self) {
        self.tab = Tab::Health;
        self.message = None;
        self.load_health();
    }

    fn load_health(&mut self) {
        self.refresh();
        let certificates = self.host.certificates();
        self.database.health = checks(
            &self.services,
            &certificates,
            self.host.database(Database::FeedsStatus),
            self.host.disk(),
            self.host.database(Database::RulesList),
            Utc::now(),
        );
        self.database
            .health
            .extend(uncovered(&certificates, &self.host.addresses()));
        // Readable as root only; as another user the line is left out.
        if let Ok(rules) = std::fs::read_to_string(crate::setup::AUDIT_RULES) {
            self.database.health.extend(audit_check(&rules));
            self.database.health.sort_by_key(|check| !check.problem);
        }
    }

    /// R reloads, Tab opens Setup, q quits.
    pub(super) fn health_key(&mut self, key: Key) {
        match key {
            Key::Char('R') => {
                self.message = None;
                self.load_health();
            }
            Key::Tab => self.open(Tab::Setup),
            Key::BackTab => self.open(Tab::Database),
            Key::Char('q') => self.quit = true,
            _ => {}
        }
    }
}
