//! Steps 9, 10 and 13: services enabled and started, firewall ports,
//! readiness and an endpoint enrollment token.

use platform_host::{
    StepState, Unit,
    runner::{
        Program::{Curl, FirewallCmd, Journalctl, Systemctl},
        Runner,
    },
};

use super::{Ctx, plan::Component};

pub(super) const READY_ATTEMPTS: u32 = 30;

fn units<R: Runner>(ctx: &Ctx<R>) -> Vec<Unit> {
    ctx.plan
        .components
        .iter()
        .flat_map(|c| c.units())
        .copied()
        .collect()
}

fn names(units: &[Unit]) -> Vec<&'static str> {
    units.iter().map(|u| u.name()).collect()
}

pub fn services_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let units = units(ctx);
    let running = units.iter().all(|unit| {
        ctx.succeeds(Systemctl, &["is-enabled", "--quiet", unit.name()])
            && ctx.succeeds(Systemctl, &["is-active", "--quiet", unit.name()])
    });
    // Running but not on a planned port (a Repair after a move), or a
    // listen address to rewrite (#72): not done.
    Ok(
        if running && super::ports::check(ctx)?.is_empty() && !super::ports::listen_stale(ctx)? {
            StepState::Done(done_text(&units))
        } else {
            StepState::Todo
        },
    )
}

fn done_text(units: &[Unit]) -> String {
    format!("enabled and started: {}", names(units).join(" "))
}

pub fn services_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    // Again here, not only at the start: the port may have been taken since.
    let mut restart = super::ports::check(ctx)?;
    for unit in super::ports::configure(ctx)? {
        if !restart.contains(&unit) {
            restart.push(unit);
        }
    }
    let units = units(ctx);
    let mut args = vec!["enable", "--now"];
    args.extend(names(&units));
    ctx.ok(Systemctl, &args)?;
    // Running on an old port or address: its configuration now says the
    // new one (try-restart leaves a stopped unit alone).
    for unit in restart {
        ctx.ok(Systemctl, &["try-restart", unit])?;
    }
    Ok(StepState::Done(done_text(&units)))
}

fn console_port<R: Runner>(ctx: &Ctx<R>) -> Result<Option<String>, String> {
    let table: toml::Table = toml::from_str(&ctx.read("/etc/openvibes/console.toml")?)
        .map_err(|error| error.to_string())?;
    if table.get("transport_mode").and_then(toml::Value::as_str) != Some("direct_tls") {
        return Ok(None); // behind a proxy: the proxy's port is not ours to open
    }
    let listen = table
        .get("development_listen")
        .and_then(toml::Value::as_str)
        .unwrap_or("0.0.0.0:443");
    let port = listen
        .parse::<std::net::SocketAddr>()
        .map_err(|error| format!("development_listen: {error}"))?
        .port();
    Ok(Some(format!("{port}/tcp")))
}

/// The firewall ports of `components`.
pub(super) fn ports_for<R: Runner>(
    ctx: &Ctx<R>,
    components: &[Component],
) -> Result<Vec<String>, String> {
    let mut ports = Vec::new();
    if components.contains(&Component::Ingest) {
        ports.push(format!("{}/tcp", ctx.plan.ingest_port));
    }
    if components.contains(&Component::Distribution) {
        ports.push(format!("{}/tcp", ctx.plan.distribution_port));
    }
    if components.contains(&Component::Console) {
        ports.extend(console_port(ctx)?);
    }
    Ok(ports)
}

fn ports<R: Runner>(ctx: &Ctx<R>) -> Result<Vec<String>, String> {
    ports_for(ctx, &ctx.plan.components)
}

pub fn firewall_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let ports = ports(ctx)?;
    if !ctx.succeeds(FirewallCmd, &["--state"]) {
        return Ok(StepState::Skipped(format!(
            "firewalld is not running; if another firewall is used, open {}",
            ports.join(" ")
        )));
    }
    let open = ports
        .iter()
        .all(|port| ctx.succeeds(FirewallCmd, &["--permanent", "--query-port", port]));
    Ok(if open {
        StepState::Done(format!("open: {}", ports.join(" ")))
    } else {
        StepState::Todo
    })
}

pub fn firewall_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let ports = ports(ctx)?;
    for port in &ports {
        if !ctx.succeeds(FirewallCmd, &["--permanent", "--query-port", port]) {
            ctx.ok(FirewallCmd, &["--permanent", "--add-port", port])?;
            // Ours to close again after a move; one open before is not.
            super::ports::record_opened(ctx, port)?;
        }
    }
    ctx.ok(FirewallCmd, &["--reload"])?;
    Ok(StepState::Done(format!("open: {}", ports.join(" "))))
}

pub(super) fn ready<R: Runner>(ctx: &Ctx<R>, unit: Unit) -> bool {
    let healthy = unit.ready_url().is_none_or(|url| {
        ctx.succeeds(
            Curl,
            &[
                "--silent",
                "--fail",
                "--max-time",
                "2",
                "--output",
                "/dev/null",
                url,
            ],
        )
    });
    healthy && listening(ctx, unit)
}

/// Whether `unit` accepts connections on its planned port too: health
/// alone answered while a moved console listened nowhere (#61). Any TLS
/// answer counts, even a refused client certificate; only "connection
/// refused" (7) and a timeout (28) do not.
fn listening<R: Runner>(ctx: &Ctx<R>, unit: Unit) -> bool {
    let Some(port) = super::ports::listen_port(ctx, unit.name()) else {
        return true;
    };
    let url = format!("https://127.0.0.1:{port}/");
    let args = [
        "--silent",
        "--insecure",
        "--max-time",
        "2",
        "--output",
        "/dev/null",
        url.as_str(),
    ];
    ctx.runner
        .run(Curl, &args)
        .is_ok_and(|out| !matches!(out.status, 7 | 28))
}

/// Spec §6: OpenVIBES does not open 514/udp (how ports are opened differs
/// per installation); when firewalld runs and it is closed, say so.
// ponytail: checks the default 514; a moved `listen` in netlog.toml is the
// admin's own change and is not re-read here.
pub(super) fn netlog_port_note<R: Runner>(ctx: &Ctx<R>) -> Option<String> {
    let planned = units(ctx).contains(&Unit::Netlog);
    if !planned || !ctx.succeeds(FirewallCmd, &["--state"]) {
        return None;
    }
    if ctx.succeeds(FirewallCmd, &["--permanent", "--query-port", "514/udp"]) {
        return None;
    }
    Some(
        "heads-up: UDP 514 is not open in firewalld, so network devices cannot reach \
         openvibes-netlog; open it the way this host manages its firewall \
         (docs/quick-setup.md, Ports)"
            .into(),
    )
}

pub fn ready_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let units = units(ctx);
    Ok(if units.iter().all(|unit| ready(ctx, *unit)) {
        StepState::Done(format!("ready: {}", names(&units).join(" ")))
    } else {
        StepState::Todo
    })
}

/// The token from `token create`'s `token X` line.
pub fn token_from(output: &str) -> Result<String, String> {
    output
        .lines()
        // "token id N" comes first; the token is the line that fits.
        .filter_map(|line| line.strip_prefix("token "))
        .find(|token| {
            token.len() == 43
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .map(str::to_owned)
        .ok_or_else(|| "token create printed no token".into())
}

/// Why `unit` is not ready after [`READY_ATTEMPTS`] seconds: the service's
/// own last message (`-u` would also match systemd's "Failed with result
/// 'exit-code'"), shared by Setup's and Update's readiness.
pub(super) fn not_ready<R: Runner>(ctx: &Ctx<R>, unit: Unit) -> String {
    let own = format!("_SYSTEMD_UNIT={}", unit.name());
    let why = ctx
        .ok(Journalctl, &[&own, "-n", "1", "-o", "cat", "--no-pager"])
        .ok()
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| format!("see journalctl -u {}", unit.name()));
    format!(
        "{} is not ready after {READY_ATTEMPTS} seconds: {why}",
        unit.name()
    )
}

pub fn ready_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let units = units(ctx);
    for unit in &units {
        let mut attempts = 0;
        while !ready(ctx, *unit) {
            attempts += 1;
            if attempts == READY_ATTEMPTS {
                return Err(not_ready(ctx, *unit));
            }
            ctx.pause();
        }
    }
    // Every service answers on its new port: the old ones can close (#69).
    let (closed, kept) = super::ports::close_moved(ctx)?;
    let mut firewall = String::new();
    if !closed.is_empty() {
        firewall = format!("; firewall closed {}", closed.join(" "));
    }
    for line in kept {
        firewall.push_str("; ");
        firewall.push_str(&line);
    }
    let mut closed = firewall;
    if let Some(note) = netlog_port_note(ctx) {
        closed.push_str("; ");
        closed.push_str(&note);
    }
    // A Repair shows no install line (it may be stale after an agent port
    // move); it is one command away.
    if ctx.repair {
        return Ok(StepState::Done(format!(
            "ready: {}{closed}; for an agent install line (new after moving an agent \
             port), run openvibes-admin agent command",
            names(&units).join(" ")
        )));
    }
    // The standing token: the console's install package and command carry
    // it. Setup no longer prints an agent line (hosts are added from the
    // console, install walkthrough 2026-10-08); `openvibes-admin agent
    // command` prints one for scripts.
    token_from(&ctx.as_admin(&["token", "fleet"])?)?;
    Ok(StepState::Done(format!(
        "ready: {}{closed}; add hosts in the console under Enrollment",
        names(&units).join(" ")
    )))
}
