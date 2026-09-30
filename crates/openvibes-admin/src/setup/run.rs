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

const READY_ATTEMPTS: u32 = 30;

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

/// What the platform serves for `set`, from the CLI's own output (rules.rs):
/// `rules list` (`SET vN keys K expires TIME [flags]`), `rules show SET`
/// (newest first: `vN sha256:… issuer ISSUER …`) and `rules trust list SET`
/// (`SET ISSUER KEY added TIME [removed TIME]`).
fn served<R: Runner>(ctx: &Ctx<R>, set: &str) -> Option<super::Served> {
    let list = ctx.as_admin(&["rules", "list"]).ok()?;
    list.lines().find(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.first() == Some(&set)
            && fields.get(1).is_some_and(|v| v.starts_with('v'))
            && !line.ends_with(" retired")
    })?;
    let show = ctx.as_admin(&["rules", "show", set]).ok()?;
    let issuer = show
        .lines()
        .next()?
        .split_whitespace()
        .skip_while(|word| *word != "issuer")
        .nth(1)?
        .to_owned();
    let keys = ctx.as_admin(&["rules", "trust", "list", set]).ok()?;
    let key = keys.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        (fields.get(1) == Some(&issuer.as_str()) && !line.contains(" removed "))
            .then(|| fields.get(2).map(|k| (*k).to_owned()))
            .flatten()
    })?;
    Some(super::Served {
        set: set.to_owned(),
        issuer,
        key,
    })
}

pub fn services_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let units = units(ctx);
    let running = units.iter().all(|unit| {
        ctx.succeeds(Systemctl, &["is-enabled", "--quiet", unit.name()])
            && ctx.succeeds(Systemctl, &["is-active", "--quiet", unit.name()])
    });
    // Running but not on a planned port (a Repair after a move): not done.
    Ok(if running && super::ports::check(ctx)?.is_empty() {
        StepState::Done(done_text(ctx, &units))
    } else {
        StepState::Todo
    })
}

fn done_text<R: Runner>(ctx: &Ctx<R>, units: &[Unit]) -> String {
    let mut text = format!("enabled and started: {}", names(units).join(" "));
    if ctx.plan.has(Component::Assistant) {
        text.push_str(
            "; start openvibes-llm after installing a model (docs/components/openvibes-llm.md)",
        );
    }
    text
}

pub fn services_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    // Again here, not only at the start: the port may have been taken since.
    let moved = super::ports::check(ctx)?;
    super::ports::configure(ctx)?;
    let units = units(ctx);
    let mut args = vec!["enable", "--now"];
    args.extend(names(&units));
    ctx.ok(Systemctl, &args)?;
    // Running on an old port: its configuration now says the new one.
    for unit in moved {
        ctx.ok(Systemctl, &["try-restart", unit])?;
    }
    Ok(StepState::Done(done_text(ctx, &units)))
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
    let Some(port) = super::ports::listen_port(ctx.plan, unit.name()) else {
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

pub fn ready_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let units = units(ctx);
    for unit in &units {
        let mut attempts = 0;
        while !ready(ctx, *unit) {
            attempts += 1;
            if attempts == READY_ATTEMPTS {
                // The service's own last message; `-u` would also match
                // systemd's "Failed with result 'exit-code'".
                let own = format!("_SYSTEMD_UNIT={}", unit.name());
                let why = ctx
                    .ok(Journalctl, &[&own, "-n", "1", "-o", "cat", "--no-pager"])
                    .ok()
                    .map(|line| line.trim().to_owned())
                    .filter(|line| !line.is_empty())
                    .unwrap_or_else(|| format!("see journalctl -u {}", unit.name()));
                return Err(format!(
                    "{} is not ready after {READY_ATTEMPTS} seconds: {why}",
                    unit.name()
                ));
            }
            ctx.pause();
        }
    }
    let token =
        token_from(&ctx.as_admin(&["token", "create", "--expires", "24h", "--uses", "10"])?)?;
    let root = ctx.read(super::pki::ROOT_CERT)?;
    let rules = ctx.read(super::BASELINE_KEY).ok().and_then(|line| {
        let set = line.split_whitespace().next()?.to_owned();
        let served: Vec<super::Served> = served(ctx, &set).into_iter().collect();
        super::published_rules_arg(&line, &served)
    });
    let command = super::agent_install_command(
        &ctx.plan.hostname,
        (ctx.plan.ingest_port, ctx.plan.distribution_port),
        &token,
        &super::pki::fingerprint(&root)?,
        rules.as_deref(),
    );
    Ok(StepState::Done(format!(
        "ready: {}; add an agent on another host (token valid 24 hours, 10 enrollments; \
         visible in its process list while it runs): {command}",
        names(&units).join(" ")
    )))
}
