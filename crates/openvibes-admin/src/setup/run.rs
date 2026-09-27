//! Steps 9, 10 and 13: services enabled and started, firewall ports,
//! readiness and an endpoint enrollment token.

use platform_host::{
    StepState, Unit,
    runner::{
        Program::{Curl, FirewallCmd, Systemctl},
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

pub fn services_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let units = units(ctx);
    let running = units.iter().all(|unit| {
        ctx.succeeds(Systemctl, &["is-enabled", "--quiet", unit.name()])
            && ctx.succeeds(Systemctl, &["is-active", "--quiet", unit.name()])
    });
    Ok(if running {
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
    let units = units(ctx);
    let mut args = vec!["enable", "--now"];
    args.extend(names(&units));
    ctx.ok(Systemctl, &args)?;
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

fn ports<R: Runner>(ctx: &Ctx<R>) -> Result<Vec<String>, String> {
    let mut ports = vec!["18423/tcp".to_owned()];
    if ctx.plan.has(Component::Distribution) {
        ports.push("18424/tcp".into());
    }
    if ctx.plan.has(Component::Console) {
        ports.extend(console_port(ctx)?);
    }
    Ok(ports)
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

fn ready<R: Runner>(ctx: &Ctx<R>, unit: Unit) -> bool {
    unit.ready_url().is_none_or(|url| {
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
    })
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
                return Err(format!(
                    "{} is not ready after {READY_ATTEMPTS} seconds; see journalctl -u {}",
                    unit.name(),
                    unit.name()
                ));
            }
            ctx.pause();
        }
    }
    let token =
        token_from(&ctx.as_admin(&["token", "create", "--expires", "24h", "--uses", "10"])?)?;
    Ok(StepState::Done(format!(
        "ready: {}; endpoint enrollment token (24 hours, 10 uses): {token}",
        names(&units).join(" ")
    )))
}

#[cfg(test)]
mod tests {
    use platform_host::{Step, StepState};

    use crate::setup::{
        fake::{Fake, plan},
        plan::Component::*,
        run_step,
    };

    const TOKEN: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

    #[test]
    fn chosen_services_are_enabled_and_started() {
        let fake = Fake::new("services");
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
        fake.answer(&["/usr/bin/systemctl", "enable", "--now"], 0, "");
        let state = run_step(
            &fake.ctx(&plan(&[Ingest, Vulns, Assistant])),
            Step::Services,
        );
        assert!(
            state.detail().contains("openvibes-llm"),
            "the model server is left to the user: {state:?}"
        );
        assert_eq!(
            fake.call(&["/usr/bin/systemctl", "enable"]),
            [
                "/usr/bin/systemctl",
                "enable",
                "--now",
                "openvibes-ingest.service",
                "openvibes-maintenance.timer",
                "openvibes-vulns.service"
            ]
        );
    }

    #[test]
    fn firewall_ports_are_opened_or_the_step_skipped() {
        let fake = Fake::new("firewall");
        fake.file(
            "/etc/openvibes/console.toml",
            "development_listen = \"0.0.0.0:8443\"\ntransport_mode = \"direct_tls\"\n",
        );
        fake.answer(&["/usr/bin/firewall-cmd", "--state"], 0, "running\n");
        fake.answer(
            &[
                "/usr/bin/firewall-cmd",
                "--permanent",
                "--query-port",
                "18423/tcp",
            ],
            0,
            "yes\n",
        );
        fake.answer(
            &["/usr/bin/firewall-cmd", "--permanent", "--query-port"],
            1,
            "no\n",
        );
        fake.answer(
            &["/usr/bin/firewall-cmd", "--permanent", "--add-port"],
            0,
            "success\n",
        );
        fake.answer(&["/usr/bin/firewall-cmd", "--reload"], 0, "success\n");
        let state = run_step(
            &fake.ctx(&plan(&[Ingest, Console, Distribution])),
            Step::Firewall,
        );
        assert_eq!(
            state,
            StepState::Done("open: 18423/tcp 18424/tcp 8443/tcp".into())
        );
        let added: Vec<String> = fake
            .calls
            .borrow()
            .iter()
            .filter(|c| c.get(2).is_some_and(|a| a == "--add-port"))
            .map(|c| c[3].clone())
            .collect();
        assert_eq!(added, ["18424/tcp", "8443/tcp"], "18423 was already open");
        assert!(fake.called(&["/usr/bin/firewall-cmd", "--reload"]));

        let fake = Fake::new("firewall-off");
        assert!(matches!(
            run_step(&fake.ctx(&plan(&[Ingest])), Step::Firewall),
            StepState::Skipped(_)
        ));
    }

    #[test]
    fn readiness_waits_then_creates_an_endpoint_token() {
        let fake = Fake::new("ready");
        fake.answer(&["/usr/bin/curl"], 0, "");
        fake.answer(
            &[
                "/usr/sbin/runuser",
                "-u",
                "openvibes-admin",
                "--",
                "/usr/bin/openvibes-admin",
                "token",
                "create",
                "--expires",
                "24h",
                "--uses",
                "10",
            ],
            0,
            &format!("token id 7\ntoken {TOKEN}\n"),
        );
        // Everything is already ready (the usual case on a first install):
        // the run still creates the endpoint token the last screen shows.
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Ready);
        assert!(state.detail().contains(TOKEN), "{state:?}");
        // Only a status check leaves the token alone.
        fake.calls.borrow_mut().clear();
        assert!(matches!(
            crate::setup::check(&fake.ctx(&plan(&[Ingest])), Step::Ready),
            StepState::Done(_)
        ));
        assert!(!fake.called(&["/usr/sbin/runuser"]));

        let fake = Fake::new("not-ready");
        fake.answer(&["/usr/bin/curl"], 7, "");
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Ready);
        assert!(
            state
                .detail()
                .contains("openvibes-ingest.service is not ready"),
            "{state:?}"
        );
    }

    #[test]
    fn tokens_are_read_from_token_create() {
        // `token create`'s real output (token.rs): the id line also starts
        // with "token ".
        assert_eq!(
            super::token_from(&format!(
                "token id 7\ntoken {TOKEN}\nThe token is shown only now; store it safely.\n"
            ))
            .unwrap(),
            TOKEN
        );
        assert!(super::token_from("token short\n").is_err());
        assert!(super::token_from("nothing\n").is_err());
    }
}
