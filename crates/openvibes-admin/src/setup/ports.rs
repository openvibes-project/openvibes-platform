//! The ports the platform listens on, and who else holds them (board #45).
//! Checked before anything changes and again before the services start, so
//! a taken port stops Setup with the holder's name instead of leaving a unit
//! that crash-loops on "Address already in use".

use platform_host::runner::{
    Program::{Ss, Systemctl},
    Runner,
};

use super::{
    Ctx,
    plan::{Component, Plan},
};

/// The console's port unless the operator chooses another.
pub const CONSOLE_DEFAULT: u16 = 443;

/// Our own fixed ports, never the console's: ingest, distribution, and the
/// loopback health listeners of ingest, distribution, console and vulns.
pub const RESERVED: [u16; 6] = [18423, 18424, 18480, 18481, 18482, 18483];

/// A console port Setup accepts.
pub fn check_console_port(port: u16) -> Result<(), String> {
    if port == 0 || RESERVED.contains(&port) {
        Err(format!(
            "console port {port} is not allowed (18423, 18424 and 18480-18483 are the platform's own)"
        ))
    } else {
        Ok(())
    }
}

/// Who listens on TCP `port` on any address, IPv4 or IPv6, `None` when
/// nobody does. Any listener counts, even on one address only: the console
/// binds every address. The process is named when `ss` may see it (as
/// root); otherwise it is "another process".
pub fn holder<R: Runner>(runner: &R, port: u16) -> Result<Option<String>, String> {
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

/// The holder in `ss -ltnpH` output: `name (pid N)` from its first
/// `users:(("name",pid=N,…))`, "another process" without one.
pub fn parse(stdout: &str) -> Option<String> {
    let line = stdout.lines().find(|line| !line.trim().is_empty())?;
    let named = line.split_once("users:((\"").and_then(|(_, rest)| {
        let (name, rest) = rest.split_once('"')?;
        let pid: String = rest
            .split_once("pid=")?
            .1
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        (!pid.is_empty()).then(|| format!("{name} (pid {pid})"))
    });
    Some(named.unwrap_or_else(|| "another process".to_owned()))
}

/// The first free port from 8443 up, for a console whose port is taken.
pub fn suggest(taken: impl Fn(u16) -> Result<bool, String>) -> Result<u16, String> {
    for port in 8443..=8543 {
        if !taken(port)? {
            return Ok(port);
        }
    }
    Err("no free port between 8443 and 8543".into())
}

/// Each port `plan` listens on: (port, the unit that owns it, what it is).
fn needed(plan: &Plan) -> Vec<(u16, &'static str, &'static str)> {
    let mut ports = Vec::new();
    if plan.has(Component::Ingest) {
        ports.push((18423, "openvibes-ingest", "ingest"));
    }
    if plan.has(Component::Distribution) {
        ports.push((18424, "openvibes-distribution", "distribution"));
    }
    if plan.has(Component::Console) {
        ports.push((plan.console_port, "openvibes-console", "the console"));
    }
    ports
}

/// The port the console is configured to listen on now, if any.
fn configured_console_port<R: Runner>(ctx: &Ctx<R>) -> Option<u16> {
    let table: toml::Table = toml::from_str(&ctx.read("/etc/openvibes/console.toml").ok()?).ok()?;
    let listen = table.get("development_listen")?.as_str()?;
    Some(listen.parse::<std::net::SocketAddr>().ok()?.port())
}

/// Refuses when a port the plan needs is held by anything but our own
/// running unit on its unchanged port (a Repair or an Update finds its own
/// services listening). A console moving to another port is checked there.
pub fn check<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    for (port, unit, what) in needed(ctx.plan) {
        let unchanged = unit != "openvibes-console" || configured_console_port(ctx) == Some(port);
        if unchanged && ctx.succeeds(Systemctl, &["is-active", "--quiet", unit]) {
            continue;
        }
        let Some(by) = holder(ctx.runner, port)? else {
            continue;
        };
        let next = if unit == "openvibes-console" {
            format!(
                "; choose another console port, e.g. {} (free)",
                suggest(|port| Ok(holder(ctx.runner, port)?.is_some()))?
            )
        } else {
            format!("; {what} needs it (stop that process first)")
        };
        return Err(format!("port {port} is taken by {by}{next}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::{
        fake::{Fake, plan},
        plan::Component::*,
    };

    const SS: &str = "/usr/sbin/ss";

    fn listens(fake: &Fake, port: u16, line: &str) {
        fake.answer(&[SS, "-ltnpH", "sport", "=", &format!(":{port}")], 0, line);
    }

    fn free(fake: &Fake) {
        fake.answer(&[SS], 0, "");
    }

    #[test]
    fn a_listener_is_named_when_ss_can_see_it() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("\n"), None);
        // The user's host (2026-09-29), unprivileged: no process shown.
        assert_eq!(
            parse("LISTEN 0      4096   *:443 *:*\n").as_deref(),
            Some("another process")
        );
        assert_eq!(
            parse(
                "LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=4242,fd=6),(\"nginx\",pid=4243,fd=6))\n"
            )
            .as_deref(),
            Some("nginx (pid 4242)")
        );
        // IPv6 only, or one address only: still taken.
        assert!(parse("LISTEN 0 128 [::]:443 [::]:*\n").is_some());
        assert!(parse("LISTEN 0 128 127.0.0.1:443 0.0.0.0:*\n").is_some());
    }

    #[test]
    fn the_console_port_is_never_one_of_ours() {
        for port in [0, 18423, 18424, 18480, 18483] {
            assert!(check_console_port(port).is_err(), "{port}");
        }
        for port in [443, 8443, 18425] {
            assert!(check_console_port(port).is_ok(), "{port}");
        }
    }

    #[test]
    fn a_taken_console_port_names_the_holder_and_a_free_one() {
        let fake = Fake::new("ports-console");
        listens(
            &fake,
            443,
            "LISTEN 0 511 *:443 *:* users:((\"nginx\",pid=7,fd=6))\n",
        );
        listens(&fake, 8443, "LISTEN 0 511 *:8443 *:*\n");
        free(&fake);
        let plan = plan(&[Ingest, Console]);
        assert_eq!(
            check(&fake.ctx(&plan)).unwrap_err(),
            "port 443 is taken by nginx (pid 7); choose another console port, e.g. 8444 (free)"
        );
    }

    #[test]
    fn a_taken_ingest_port_stops_setup() {
        let fake = Fake::new("ports-ingest");
        listens(&fake, 18423, "LISTEN 0 5 0.0.0.0:18423 0.0.0.0:*\n");
        free(&fake);
        let plan = plan(&[Ingest, Distribution]);
        assert_eq!(
            check(&fake.ctx(&plan)).unwrap_err(),
            "port 18423 is taken by another process; ingest needs it (stop that process first)"
        );
    }

    #[test]
    fn our_own_running_units_and_free_ports_pass() {
        let fake = Fake::new("ports-own");
        fake.answer(
            &[
                "/usr/bin/systemctl",
                "is-active",
                "--quiet",
                "openvibes-ingest",
            ],
            0,
            "",
        );
        listens(&fake, 18423, "LISTEN 0 5 0.0.0.0:18423 0.0.0.0:*\n");
        free(&fake);
        let mut plan = plan(&[Ingest, Distribution, Console]);
        plan.console_port = 8443;
        check(&fake.ctx(&plan)).unwrap();
        assert!(fake.called(&[SS, "-ltnpH", "sport", "=", ":8443"]));
        assert!(!fake.called(&[SS, "-ltnpH", "sport", "=", ":443"]));
    }

    #[test]
    fn services_do_not_start_on_a_taken_port() {
        let fake = Fake::new("ports-services");
        listens(&fake, 443, "LISTEN 0 511 *:443 *:*\n");
        free(&fake);
        fake.answer(&["/usr/bin/systemctl", "is-enabled"], 1, "");
        fake.answer(&["/usr/bin/systemctl", "enable", "--now"], 0, "");
        let state = crate::setup::run_step(
            &fake.ctx(&plan(&[Ingest, Console])),
            platform_host::Step::Services,
        );
        assert!(
            matches!(&state, platform_host::StepState::Failed(e) if e.starts_with("port 443 is taken by another process")),
            "{state:?}"
        );
        assert!(!fake.called(&["/usr/bin/systemctl", "enable"]));
    }

    #[test]
    fn readiness_quotes_why_a_service_is_down() {
        let fake = Fake::new("ports-ready");
        fake.answer(&["/usr/bin/curl"], 7, "");
        // The service's own messages, not systemd's "Failed with result".
        fake.answer(
            &[
                "/usr/bin/journalctl",
                "_SYSTEMD_UNIT=openvibes-ingest.service",
                "-n",
                "1",
                "-o",
                "cat",
                "--no-pager",
            ],
            0,
            "console listener failed: Address already in use (os error 98)\n",
        );
        fake.answer(
            &["/usr/bin/journalctl"],
            0,
            "openvibes-ingest.service: Failed with result 'exit-code'.\n",
        );
        let state = crate::setup::run_step(
            &fake.ctx(&plan(&[Ingest, Console])),
            platform_host::Step::Ready,
        );
        assert_eq!(
            state,
            platform_host::StepState::Failed(
                "openvibes-ingest.service is not ready after 30 seconds: \
                 console listener failed: Address already in use (os error 98)"
                    .into()
            )
        );
    }

    #[test]
    fn a_running_console_moving_to_a_taken_port_is_refused() {
        let fake = Fake::new("ports-move");
        // Repair: the console runs on 443; the plan now wants 8443.
        fake.file(
            "/etc/openvibes/console.toml",
            "development_listen = \"0.0.0.0:443\"\ntransport_mode = \"direct_tls\"\n",
        );
        fake.answer(&["/usr/bin/systemctl", "is-active"], 0, "");
        listens(&fake, 8443, "LISTEN 0 511 *:8443 *:*\n");
        free(&fake);
        let mut plan = plan(&[Ingest, Console]);
        plan.console_port = 8443;
        assert!(
            check(&fake.ctx(&plan))
                .unwrap_err()
                .starts_with("port 8443 is taken by another process"),
        );
        // Unchanged, the running console's own port passes.
        plan.console_port = 443;
        check(&fake.ctx(&plan)).unwrap();
    }

    #[test]
    fn a_failing_ss_is_an_error_not_a_free_port() {
        let fake = Fake::new("ports-ss-fails");
        let plan = plan(&[Ingest]);
        assert!(
            check(&fake.ctx(&plan))
                .unwrap_err()
                .contains("could not list")
        );
    }
}
