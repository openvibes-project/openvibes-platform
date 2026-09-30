//! The ports the platform listens on, and who else holds them (boards #45,
//! #48). Checked before anything changes and again before the services
//! start, so a taken port stops Setup with the holder's name instead of
//! leaving a unit that crash-loops on "Address already in use".

use platform_host::{
    Service,
    runner::{
        Program::{Ss, Systemctl},
        Runner,
    },
};

use super::{Ctx, plan::Component};
use crate::config_file;

/// The console's port unless the operator chooses another.
pub const CONSOLE_DEFAULT: u16 = 443;
/// Ingest's port unless the operator chooses another.
pub const INGEST_DEFAULT: u16 = 18423;
/// Distribution's port unless the operator chooses another.
pub const DISTRIBUTION_DEFAULT: u16 = 18424;

/// The platform's fixed loopback ports, never a chosen one: the assistant's
/// model server and the health listeners of ingest, distribution, console
/// and vulns.
pub const RESERVED: [u16; 5] = [18430, 18480, 18481, 18482, 18483];

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
                "{what} port {port} is not allowed (18430 and 18480-18483 are the platform's own)"
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

/// Writes the plan's ingest and distribution ports into their services'
/// `listen` (the console's is the Console step's).
pub fn configure<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    for (component, service, port) in [
        (Component::Ingest, Service::Ingest, ctx.plan.ingest_port),
        (
            Component::Distribution,
            Service::Distribution,
            ctx.plan.distribution_port,
        ),
    ] {
        let path = format!("/etc/openvibes/{}", service.file_name());
        if !ctx.plan.has(component) || !ctx.exists(&path) {
            continue;
        }
        let mut doc: toml_edit::DocumentMut = ctx
            .read(&path)?
            .parse()
            .map_err(|error| format!("{path}: {error}"))?;
        let listen = format!("0.0.0.0:{port}");
        if doc.get("listen").and_then(|v| v.as_str()) != Some(listen.as_str()) {
            doc["listen"] = toml_edit::value(listen);
            config_file::replace(&ctx.path("/etc/openvibes"), service, &doc.to_string())?;
        }
    }
    Ok(())
}

/// The port `unit` (e.g. `openvibes-console.service`) listens on for
/// agents or browsers, for readiness.
pub fn listen_port<R: Runner>(ctx: &Ctx<R>, unit: &str) -> Option<u16> {
    let name = unit.trim_end_matches(".service");
    needed(ctx).into_iter().find(|n| n.1 == name).map(|n| n.0)
}
