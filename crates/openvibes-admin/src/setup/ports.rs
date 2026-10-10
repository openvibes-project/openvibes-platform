//! The ports the platform listens on, and who else holds them (boards #45,
//! #48). Checked before anything changes and again before the services
//! start, so a taken port stops Setup with the holder's name instead of
//! leaving a unit that crash-loops on "Address already in use".

use std::path::Path;

use platform_host::{
    Service,
    runner::{
        Program::{FirewallCmd, Ss, Systemctl},
        Runner,
    },
};

use super::{
    Ctx,
    plan::{Component, Plan},
};
use crate::config_file;

/// The console's port unless the operator chooses another.
pub const CONSOLE_DEFAULT: u16 = 443;
/// Ingest's port unless the operator chooses another.
pub const INGEST_DEFAULT: u16 = 18423;
/// Distribution's port unless the operator chooses another.
pub const DISTRIBUTION_DEFAULT: u16 = 18424;

/// The platform's fixed loopback ports, never a chosen one: the assistant's
/// model server and the health listeners of ingest, distribution, console
/// vulns and netlog.
pub const RESERVED: [u16; 6] = [18430, 18480, 18481, 18482, 18483, 18484];

/// The plan's three listen ports: each a real port, none of the fixed
/// ones, all different.
pub fn check_ports(console: u16, ingest: u16, distribution: u16) -> Result<(), String> {
    for (what, port) in [
        ("console", console),
        ("ingest", ingest),
        ("distribution", distribution),
    ] {
        if port == 0 {
            return Err(format!("{what} port 0 is not a port"));
        }
        if RESERVED.contains(&port) {
            return Err(format!(
                "{what} port {port} is not allowed (18430 and 18480-18484 are the platform's own)"
            ));
        }
    }
    if console == ingest || console == distribution || ingest == distribution {
        return Err("the console, ingest and distribution ports must differ".into());
    }
    Ok(())
}

/// Who listens on TCP `port` on any address, IPv4 or IPv6, `None` when
/// nobody does, as (label, pid). Any listener counts, even on one address
/// only: our services bind every address. The process and its pid are
/// known when `ss` may see them (as root); otherwise it is "another
/// process".
pub fn holder<R: Runner>(runner: &R, port: u16) -> Result<Option<(String, Option<u32>)>, String> {
    let filter = format!(":{port}");
    let out = runner
        .run(Ss, &["-ltnpH", "sport", "=", &filter])
        .map_err(|error| format!("{}: {error}", Ss.path()))?;
    if out.status != 0 {
        return Err(format!(
            "{} could not list listening ports: {}",
            Ss.path(),
            out.stderr.trim()
        ));
    }
    Ok(parse(&out.stdout))
}

/// The holder in `ss -ltnpH` output: `name (pid N)` and N from its first
/// `users:(("name",pid=N,…))`, "another process" without one.
pub fn parse(stdout: &str) -> Option<(String, Option<u32>)> {
    let line = stdout.lines().find(|line| !line.trim().is_empty())?;
    let named = line.split_once("users:((\"").and_then(|(_, rest)| {
        let (name, rest) = rest.split_once('"')?;
        let pid: String = rest
            .split_once("pid=")?
            .1
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let pid: u32 = pid.parse().ok()?;
        Some((format!("{name} (pid {pid})"), Some(pid)))
    });
    Some(named.unwrap_or_else(|| ("another process".to_owned(), None)))
}

/// The first free port from `from` up, for a chosen port that is taken.
pub fn suggest(from: u16, taken: impl Fn(u16) -> Result<bool, String>) -> Result<u16, String> {
    let to = from.saturating_add(100);
    for port in from..=to {
        if !RESERVED.contains(&port) && !taken(port)? {
            return Ok(port);
        }
    }
    Err(format!("no free port between {from} and {to}"))
}

/// Where a suggestion for each kind of port starts.
fn suggest_from(unit: &str) -> u16 {
    if unit == "openvibes-console" {
        8443
    } else {
        18425
    }
}

/// Each port the plan listens on: (port, the unit that owns it, what it
/// is). A console behind a reverse proxy is left out: its public port is
/// the proxy's (a missing `console.toml`, before the packages, is direct).
pub fn needed<R: Runner>(ctx: &Ctx<R>) -> Vec<(u16, &'static str, &'static str)> {
    let plan = ctx.plan;
    let mut ports = Vec::new();
    if plan.has(Component::Ingest) {
        ports.push((plan.ingest_port, "openvibes-ingest", "ingest"));
    }
    if plan.has(Component::Distribution) {
        ports.push((
            plan.distribution_port,
            "openvibes-distribution",
            "distribution",
        ));
    }
    if plan.has(Component::Console) && direct_tls(ctx) {
        ports.push((plan.console_port, "openvibes-console", "the console"));
    }
    ports
}

/// Whether the console serves TLS itself, rather than behind a proxy.
fn direct_tls<R: Runner>(ctx: &Ctx<R>) -> bool {
    let Ok(text) = ctx.read("/etc/openvibes/console.toml") else {
        return true;
    };
    toml::from_str::<toml::Table>(&text).map_or(true, |table| {
        table.get("transport_mode").and_then(toml::Value::as_str) == Some("direct_tls")
    })
}

/// The main process of `unit` while it runs.
fn main_pid<R: Runner>(ctx: &Ctx<R>, unit: &str) -> Option<u32> {
    ctx.ok(Systemctl, &["show", "--property=MainPID", "--value", unit])
        .ok()?
        .trim()
        .parse()
        .ok()
        .filter(|pid| *pid != 0)
}

/// Refuses when a port the plan needs is held by anything but the unit
/// that owns it (its main process: a Repair or an Update finds our own
/// services listening). Returns the running units that do not listen on
/// their planned port yet: restart them once their configuration says it.
pub fn check<R: Runner>(ctx: &Ctx<R>) -> Result<Vec<&'static str>, String> {
    let mut restart = Vec::new();
    let needed = needed(ctx);
    for &(port, unit, what) in &needed {
        let own = main_pid(ctx, unit);
        match holder(ctx.runner, port)? {
            None if own.is_some() => restart.push(unit),
            None => {}
            Some((_, pid)) if pid.is_some() && pid == own => {}
            Some((by, _)) => {
                let free = suggest(suggest_from(unit), |port| {
                    Ok(holder(ctx.runner, port)?.is_some() || needed.iter().any(|n| n.0 == port))
                })?;
                return Err(format!(
                    "port {port} is taken by {by}; {what} needs it: stop that process or choose another port, e.g. {free} (free)"
                ));
            }
        }
    }
    Ok(restart)
}

/// The ingest and distribution configs whose `listen` is not the plan's
/// (a moved port, or `0.0.0.0` before dual stack, #72): `(unit, path,
/// service, listen)`.
fn stale<R: Runner>(ctx: &Ctx<R>) -> Result<Vec<(&'static str, String, Service, String)>, String> {
    let mut stale = Vec::new();
    for (component, service, unit, port) in [
        (
            Component::Ingest,
            Service::Ingest,
            "openvibes-ingest",
            ctx.plan.ingest_port,
        ),
        (
            Component::Distribution,
            Service::Distribution,
            "openvibes-distribution",
            ctx.plan.distribution_port,
        ),
    ] {
        let path = format!("/etc/openvibes/{}", service.file_name());
        if !ctx.plan.has(component) || !ctx.exists(&path) {
            continue;
        }
        let doc: toml::Table =
            toml::from_str(&ctx.read(&path)?).map_err(|error| format!("{path}: {error}"))?;
        let listen = any_address(ctx, port);
        if doc.get("listen").and_then(toml::Value::as_str) != Some(listen.as_str()) {
            stale.push((unit, path, service, listen));
        }
    }
    Ok(stale)
}

/// Whether a `listen` differs from the plan's, so the services step is not
/// done even with every unit running on its port (#72 on an existing host).
pub fn listen_stale<R: Runner>(ctx: &Ctx<R>) -> Result<bool, String> {
    Ok(!stale(ctx)?.is_empty())
}

/// Writes the plan's ingest and distribution ports into their services'
/// `listen` (the console's is the Console step's); the units whose file
/// changed, which a running unit only reads on a restart.
pub fn configure<R: Runner>(ctx: &Ctx<R>) -> Result<Vec<&'static str>, String> {
    let mut changed = Vec::new();
    for (unit, path, service, listen) in stale(ctx)? {
        let mut doc: toml_edit::DocumentMut = ctx
            .read(&path)?
            .parse()
            .map_err(|error| format!("{path}: {error}"))?;
        doc["listen"] = toml_edit::value(listen);
        config_file::replace(&ctx.path("/etc/openvibes"), service, &doc.to_string())?;
        changed.push(unit);
    }
    Ok(changed)
}

/// Every address at `port`: `[::]` where it takes IPv4 too (IPv6 on and
/// `bindv6only` 0, Fedora's default), so a name resolving to IPv6 only
/// reaches the services (board #72); `0.0.0.0` otherwise, since binding
/// `[::]` without IPv6 fails and with `bindv6only` 1 would drop IPv4.
pub(crate) fn any_address<R: Runner>(ctx: &Ctx<R>, port: u16) -> String {
    match ctx.read("/proc/sys/net/ipv6/bindv6only") {
        Ok(value) if value.trim() == "0" => format!("[::]:{port}"),
        _ => format!("0.0.0.0:{port}"),
    }
}

/// The port `unit` (e.g. `openvibes-console.service`) listens on for
/// agents or browsers, for readiness.
pub fn listen_port<R: Runner>(ctx: &Ctx<R>, unit: &str) -> Option<u16> {
    let name = unit.trim_end_matches(".service");
    needed(ctx).into_iter().find(|n| n.1 == name).map(|n| n.0)
}

/// The agent ports a Repair moves from `old` to `new`, as (what, old, new):
/// agents enrolled from other hosts keep calling the old ones.
pub fn moved_agent_ports(old: &Plan, new: &Plan) -> Vec<(&'static str, u16, u16)> {
    [
        ("ingest", old.ingest_port, new.ingest_port),
        ("distribution", old.distribution_port, new.distribution_port),
    ]
    .into_iter()
    .filter(|(_, from, to)| from != to)
    .collect()
}

/// The firewalld ports Setup itself opened, one `PORT/tcp` per line: the
/// only ones a move may close (lead on #106: a port that was open before
/// Setup ran, e.g. 443 for another web server, is not ours to close).
/// Installs from before this record have none, so nothing is closed there.
pub const OPENED: &str = "/etc/openvibes/setup-opened-ports";

fn opened<R: Runner>(ctx: &Ctx<R>) -> Vec<String> {
    ctx.read(OPENED)
        .map(|text| text.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

fn write_opened<R: Runner>(ctx: &Ctx<R>, ports: &[String]) -> Result<(), String> {
    let text: String = ports.iter().map(|port| format!("{port}\n")).collect();
    ctx.put(OPENED, text.as_bytes(), None, 0o644)
}

/// Records that the Firewall step opened `port`.
pub fn record_opened<R: Runner>(ctx: &Ctx<R>, port: &str) -> Result<(), String> {
    let mut ports = opened(ctx);
    if !ports.iter().any(|known| known == port) {
        ports.push(port.to_owned());
        write_opened(ctx, &ports)?;
    }
    Ok(())
}

/// Where `helper setup-plan` keeps the ports a TUI plan moves away from,
/// `CONSOLE INGEST DISTRIBUTION`, until the run ends well (#69: the CLI's
/// Repair closes them itself; the TUI saves the plan first, then runs).
pub const MOVED_FROM: &str = "/etc/openvibes/setup-moved-from";

/// Remembers `old`'s ports when `new` moves any of them; keeps an earlier
/// record (a run that did not finish), so the first ports are the ones
/// closed.
pub fn remember_moved(root: &Path, old: &Plan, new: &Plan) -> Result<(), String> {
    let from = [old.console_port, old.ingest_port, old.distribution_port];
    let file = root.join(MOVED_FROM.trim_start_matches('/'));
    if from == [new.console_port, new.ingest_port, new.distribution_port] || file.exists() {
        return Ok(());
    }
    let text = format!("{} {} {}\n", from[0], from[1], from[2]);
    std::fs::write(&file, text).map_err(|error| format!("{}: {error}", file.display()))
}

/// After a run whose services are all ready: closes the ports recorded by
/// [`remember_moved`] as the CLI's Repair does, then forgets them. What
/// it closed and kept, as [`close_old`].
pub fn close_moved<R: Runner>(ctx: &Ctx<R>) -> Result<(Vec<String>, Vec<String>), String> {
    let Ok(text) = ctx.read(MOVED_FROM) else {
        return Ok((Vec::new(), Vec::new()));
    };
    let ports: Vec<u16> = text
        .split_whitespace()
        .filter_map(|port| port.parse().ok())
        .collect();
    let outcome = match ports[..] {
        [console_port, ingest_port, distribution_port] => {
            let old = Plan {
                console_port,
                ingest_port,
                distribution_port,
                ..ctx.plan.clone()
            };
            close_old(ctx, &old)?
        }
        _ => (Vec::new(), Vec::new()),
    };
    let file = ctx.path(MOVED_FROM);
    std::fs::remove_file(&file).map_err(|error| format!("{}: {error}", file.display()))?;
    Ok(outcome)
}

/// Closes in firewalld the ports a Repair moved away from (`old`'s, no
/// longer the plan's) that are open; the Firewall step opens the new ones.
/// Only ports Setup opened ([`OPENED`]) are candidates.
/// A port another program still listens on stays open (reviewer on #106:
/// on the user's host nginx serves the 443 Setup once opened), and so does
/// one `ss` cannot check. Returns what it closed and why others stayed;
/// without firewalld, nothing.
pub fn close_old<R: Runner>(
    ctx: &Ctx<R>,
    old: &Plan,
) -> Result<(Vec<String>, Vec<String>), String> {
    if !ctx.succeeds(FirewallCmd, &["--state"]) {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut kept = Vec::new();
    let mut ours = opened(ctx);
    let new = ctx.plan;
    let still = [new.console_port, new.ingest_port, new.distribution_port];
    let mut closed = Vec::new();
    for from in [old.console_port, old.ingest_port, old.distribution_port] {
        // A port another service moved onto stays open.
        let port = format!("{from}/tcp");
        if still.contains(&from)
            || !ours.contains(&port)
            || !ctx.succeeds(FirewallCmd, &["--permanent", "--query-port", &port])
        {
            continue;
        }
        // Our services left it after Readiness: whoever listens is not us.
        match holder(ctx.runner, from) {
            Ok(None) => {
                ctx.ok(FirewallCmd, &["--permanent", "--remove-port", &port])?;
                ours.retain(|known| *known != port);
                write_opened(ctx, &ours)?;
                closed.push(port);
            }
            Ok(Some((who, _))) => kept.push(format!("{port} stays open: {who} uses it")),
            Err(error) => kept.push(format!("{port} stays open: {error}")),
        }
    }
    if !closed.is_empty() {
        // The running firewall too, not only after a reboot.
        ctx.ok(FirewallCmd, &["--reload"])?;
    }
    Ok((closed, kept))
}
