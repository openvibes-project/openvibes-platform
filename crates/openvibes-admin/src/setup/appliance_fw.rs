//! The Firewall step on the appliance (#561, ruling #556): firewalld opens
//! exactly the ports OpenVIBES uses, 514/udp for network devices, and the
//! SSH port the plan chose; every other port and service in the default
//! zone is closed, except dhcpv6-client (ruling on #561: without it the
//! appliance gets no IPv6 address from DHCPv6). sshd moves to the plan's
//! port in the same step, so the port SSH listens on is the one open.
//!
//! A new SSH port is written as an `sshd_config.d` drop-in, labelled for
//! SELinux, checked with `sshd -t` and reloaded; the previous drop-in comes
//! back if any of that fails. Sessions already signed in stay connected.
// ponytail: only the default zone's ports and services are made exact;
// rich rules, sources and forwards an admin added by hand are left alone.

use platform_host::runner::{
    Program::{FirewallCmd, Semanage, Sshd, Systemctl},
    Runner,
};

use super::{Ctx, StepState, run};

/// The services the appliance keeps open besides its ports.
const KEEP: [&str; 1] = ["dhcpv6-client"];

/// sshd's port drop-in; sshd takes the first `Port` it reads, and the
/// main `sshd_config` includes this folder first.
pub const SSH_PORT: &str = "/etc/ssh/sshd_config.d/01-openvibes-port.conf";

pub(super) fn on_appliance<R: Runner>(ctx: &Ctx<R>) -> bool {
    ctx.exists(platform_host::setup::APPLIANCE_FILE)
}

/// The ports open on the appliance: OpenVIBES', network devices', SSH.
pub(super) fn wanted<R: Runner>(ctx: &Ctx<R>) -> Result<Vec<String>, String> {
    let mut ports = run::ports_for(ctx, &ctx.plan.components)?;
    if run::units(ctx).contains(&platform_host::Unit::Netlog) {
        ports.push("514/udp".into());
    }
    ports.push(format!("{}/tcp", ctx.plan.ssh_port));
    Ok(ports)
}

fn listed<R: Runner>(ctx: &Ctx<R>, what: &str) -> Result<Vec<String>, String> {
    let out = ctx.ok(FirewallCmd, &["--permanent", what])?;
    Ok(out.split_whitespace().map(str::to_owned).collect())
}

/// The ports sshd listens on, from `sshd -T`.
fn ssh_ports<R: Runner>(ctx: &Ctx<R>) -> Result<Vec<u16>, String> {
    let out = ctx.ok(Sshd, &["-T"])?;
    Ok(out
        .lines()
        .filter_map(|line| line.strip_prefix("port ")?.trim().parse().ok())
        .collect())
}

pub(super) fn check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let wanted = wanted(ctx)?;
    if !ctx.succeeds(FirewallCmd, &["--state"]) {
        return Ok(StepState::Todo);
    }
    let mut ports = listed(ctx, "--list-ports")?;
    let mut want = wanted.clone();
    ports.sort();
    want.sort();
    let exact = ports == want
        && listed(ctx, "--list-services")?
            .iter()
            .all(|service| KEEP.contains(&service.as_str()))
        && ssh_ports(ctx)? == [ctx.plan.ssh_port];
    Ok(if exact {
        StepState::Done(done(&wanted))
    } else {
        StepState::Todo
    })
}

fn done(ports: &[String]) -> String {
    format!("open: {}; nothing else", ports.join(" "))
}

pub(super) fn apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let wanted = wanted(ctx)?;
    if ssh_ports(ctx)? != [ctx.plan.ssh_port] {
        move_ssh(ctx, ctx.plan.ssh_port)?;
    }
    if !ctx.succeeds(FirewallCmd, &["--state"]) {
        ctx.ok(Systemctl, &["enable", "--now", "firewalld.service"])?;
    }
    // Permanent changes first, one reload: the running firewall never
    // has SSH closed in between.
    for service in listed(ctx, "--list-services")? {
        if !KEEP.contains(&service.as_str()) {
            ctx.ok(FirewallCmd, &["--permanent", "--remove-service", &service])?;
        }
    }
    let open = listed(ctx, "--list-ports")?;
    for port in open.iter().filter(|port| !wanted.contains(port)) {
        ctx.ok(FirewallCmd, &["--permanent", "--remove-port", port])?;
    }
    for port in wanted.iter().filter(|port| !open.contains(port)) {
        ctx.ok(FirewallCmd, &["--permanent", "--add-port", port])?;
    }
    ctx.ok(FirewallCmd, &["--reload"])?;
    Ok(StepState::Done(done(&wanted)))
}

/// Moves sshd to `port`; on any failure the previous drop-in comes back.
fn move_ssh<R: Runner>(ctx: &Ctx<R>, port: u16) -> Result<(), String> {
    let previous = ctx.read(SSH_PORT).ok();
    let put_back = || match &previous {
        Some(text) => ctx.put(SSH_PORT, text.as_bytes(), None, 0o600),
        None => remove(ctx),
    };
    let fail = |why: String| put_back().and(Err(why));
    if port == 22 {
        remove(ctx)?;
    } else {
        ctx.put(SSH_PORT, format!("Port {port}\n").as_bytes(), None, 0o600)?;
        let number = port.to_string();
        let label = |how: &str| {
            ctx.succeeds(
                Semanage,
                &["port", how, "-t", "ssh_port_t", "-p", "tcp", &number],
            )
        };
        // -a for a port with no type yet, -m for one another type holds.
        if !label("-a") && !label("-m") {
            return fail(format!("SELinux would not let SSH use port {port}"));
        }
    }
    if let Err(why) = ctx.ok(Sshd, &["-t"]) {
        return fail(format!("sshd would not accept port {port}: {why}"));
    }
    if let Err(why) = ctx.ok(Systemctl, &["reload", "sshd.service"]) {
        return fail(format!("sshd did not reload on port {port}: {why}"));
    }
    Ok(())
}

fn remove<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    match std::fs::remove_file(ctx.path(SSH_PORT)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("{SSH_PORT}: {error}"))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
#[path = "appliance_fw_tests.rs"]
mod tests;
