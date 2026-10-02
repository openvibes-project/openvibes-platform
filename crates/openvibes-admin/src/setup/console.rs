//! Step 8: the console's public origin and the first admin account
//! (packaging.md "Console RPM setup"). The TLS files come from step 7.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use platform_host::{
    Service, StepState,
    runner::{
        Program::{Runuser, Systemctl, Usermod},
        Runner,
    },
};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use super::{Ctx, plan::Component};
use crate::config_file;

const CONSOLE_TOML: &str = "/etc/openvibes/console.toml";

/// The console's URL: the port only when it is not HTTPS's own.
fn origin<R: Runner>(ctx: &Ctx<R>) -> String {
    match ctx.plan.console_port {
        443 => format!("https://{}", ctx.plan.hostname),
        port => format!("https://{}:{port}", ctx.plan.hostname),
    }
}

fn listen<R: Runner>(ctx: &Ctx<R>) -> String {
    super::ports::any_address(ctx, ctx.plan.console_port)
}

/// The origin, and with direct TLS the listener, are the plan's. Behind a
/// proxy the listener is the proxy's business.
fn origin_set<R: Runner>(ctx: &Ctx<R>) -> Result<bool, String> {
    let table: toml::Table = toml::from_str(&ctx.read(CONSOLE_TOML)?)
        .map_err(|error| format!("{CONSOLE_TOML}: {error}"))?;
    let text = |key: &str| table.get(key).and_then(toml::Value::as_str);
    Ok(text("public_origin") == Some(origin(ctx).as_str())
        && (text("transport_mode") != Some("direct_tls")
            || text("development_listen") == Some(listen(ctx).as_str())))
}

fn admin_exists<R: Runner>(ctx: &Ctx<R>) -> Result<bool, String> {
    Ok(ctx
        .as_admin(&["user", "list"])?
        .lines()
        .skip(1)
        .any(|line| line.split('\t').next() == Some("admin")))
}

const SIGNER_DIR: &str = "/var/lib/openvibes-signer";
const SIGNER_CLIENTS: &str = "openvibes-signer-clients";
/// Who may reach the signer's socket: the console, and the admin CLI
/// (`rules publish-site`). The signer's own password, permission and limit
/// checks are the boundary, not the group (lead, #2110).
const SIGNER_USERS: [&str; 2] = ["openvibes-console", "openvibes-admin"];

/// The signer (own rules, board #107): its site key and version state
/// exist, and the console may reach its socket.
fn signer_ready<R: Runner>(ctx: &Ctx<R>) -> Result<bool, String> {
    if !ctx.plan.has(Component::Signer) {
        return Ok(true);
    }
    let groups = ctx.read("/etc/group")?;
    let members = groups
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{SIGNER_CLIENTS}:")))
        .and_then(|rest| rest.rsplit(':').next())
        .unwrap_or("");
    let joined = SIGNER_USERS
        .iter()
        .all(|user| members.split(',').any(|m| m == *user));
    Ok(joined
        && ctx.exists(&format!("{SIGNER_DIR}/site.key"))
        && ctx.exists(&format!("{SIGNER_DIR}/versions.json"))
        && ctx.exists(super::SITE_KEY))
}

/// Creates the site key and version state as the signer's user (the next
/// version signed is 1; an existing state is kept), and lets the console
/// reach the signer's socket.
fn signer_apply<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    let lines = ctx.ok(
        Runuser,
        &[
            "-u",
            "openvibes-signer",
            "-g",
            SIGNER_CLIENTS,
            "--",
            "/usr/bin/openvibes-signer",
            "seed",
            "--min-version",
            "1",
        ],
    )?;
    // Exactly the two trust lines, each one `rules_arg` accepts, before
    // they are saved for `agent command`.
    let trust: Vec<&str> = lines.lines().collect();
    let sets: Vec<&str> = trust
        .iter()
        .filter(|line| super::rules_arg(line).is_some())
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    if sets != ["site", "site-alarms"] {
        return Err(format!(
            "openvibes-signer seed printed no trust lines: {lines:?}"
        ));
    }
    // Distribution must trust the key before it serves a site bundle.
    for line in &trust {
        let fields: Vec<&str> = line.split_whitespace().collect();
        ctx.as_admin(&["rules", "trust", "add", fields[0], fields[1], fields[2]])?;
    }
    ctx.put(super::SITE_KEY, lines.as_bytes(), None, 0o644)?;
    for user in SIGNER_USERS {
        ctx.ok(Usermod, &["-aG", SIGNER_CLIENTS, user])?;
    }
    // The console's group list is read at start.
    ctx.ok(Systemctl, &["try-restart", "openvibes-console"])?;
    Ok(())
}

fn signer_note<R: Runner>(ctx: &Ctx<R>) -> &'static str {
    if ctx.plan.has(Component::Signer) {
        " · rule signer ready"
    } else {
        ""
    }
}

pub fn console_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Console) {
        return Ok(StepState::Skipped("console not chosen".into()));
    }
    Ok(
        if origin_set(ctx)? && admin_exists(ctx)? && signer_ready(ctx)? {
            StepState::Done(format!(
                "{} · console admin: admin{}",
                origin(ctx),
                signer_note(ctx)
            ))
        } else {
            StepState::Todo
        },
    )
}

/// 24 characters, base64url of 18 random bytes.
fn generated_password() -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new([0_u8; 18]);
    SystemRandom::new()
        .fill(&mut *bytes)
        .map_err(|_| "could not generate a password".to_owned())?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(*bytes)))
}

pub fn console_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Console) {
        return console_check(ctx);
    }
    if !origin_set(ctx)? {
        let mut doc: toml_edit::DocumentMut = ctx
            .read(CONSOLE_TOML)?
            .parse()
            .map_err(|error| format!("{CONSOLE_TOML}: {error}"))?;
        doc["public_origin"] = toml_edit::value(origin(ctx));
        if doc.get("transport_mode").and_then(|v| v.as_str()) == Some("direct_tls") {
            doc["development_listen"] = toml_edit::value(listen(ctx));
        }
        config_file::replace(
            &ctx.path("/etc/openvibes"),
            Service::Console,
            &doc.to_string(),
        )?;
        // A running console reads it only on a restart (#72: `[::]` on an
        // existing host); try-restart leaves a stopped one alone.
        ctx.ok(Systemctl, &["try-restart", "openvibes-console"])?;
    }
    if !signer_ready(ctx)? {
        signer_apply(ctx)?;
    }
    let mut shown = "console admin: admin".to_owned();
    if !admin_exists(ctx)? {
        let (password, generated) = match &ctx.plan.admin_password_file {
            Some(file) => {
                let text = Zeroizing::new(ctx.read(&file.display().to_string())?);
                (
                    Zeroizing::new(text.lines().next().unwrap_or("").to_owned()),
                    false,
                )
            }
            None => (generated_password()?, true),
        };
        let input = Zeroizing::new(format!("{}\n", *password));
        ctx.as_admin_with_input(
            &[
                "user",
                "create",
                "--username",
                "admin",
                "--display-name",
                "Administrator",
                "--role",
                "admin",
                "--password-stdin",
            ],
            input.as_bytes(),
        )?;
        if generated {
            shown = format!(
                "console admin: admin, password {} (shown only now; change it after logging in)",
                *password
            );
        }
    }
    Ok(StepState::Done(format!(
        "{} · {shown}{}",
        origin(ctx),
        signer_note(ctx)
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

    const ADMIN: [&str; 5] = [
        "/usr/sbin/runuser",
        "-u",
        "openvibes-admin",
        "--",
        "/usr/bin/openvibes-admin",
    ];

    fn console(fake: &Fake) {
        fake.file(
            "/etc/openvibes/console.toml",
            &format!(
                "# kept by Setup\n{}",
                include_str!("../../../../packaging/rpm/console.toml")
            ),
        );
        fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
        fake.answer(
            &[&ADMIN[..], &["user", "list"]].concat(),
            0,
            "USERNAME\tSTATUS\tROLES\tDISPLAY NAME\tLAST SEEN\n",
        );
        fake.answer(
            &[&ADMIN[..], &["user", "create"]].concat(),
            0,
            "created admin\n",
        );
    }

    #[test]
    fn the_origin_is_set_and_an_admin_created_with_a_generated_password() {
        let fake = Fake::new("console");
        console(&fake);
        let state = run_step(&fake.ctx(&plan(&[Ingest, Console])), Step::Console);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(
            fake.text("/etc/openvibes/console.toml")
                .contains("public_origin = \"https://platform.example.com\"")
        );
        assert!(
            fake.text("/etc/openvibes/console.toml")
                .contains("# kept by Setup"),
            "comments kept"
        );
        let create = fake.call(&[&ADMIN[..], &["user", "create"]].concat());
        assert_eq!(
            create[5..],
            [
                "user",
                "create",
                "--username",
                "admin",
                "--display-name",
                "Administrator",
                "--role",
                "admin",
                "--password-stdin"
            ]
        );
        let password = fake.inputs.borrow()[0].trim_end().to_owned();
        assert_eq!(password.len(), 24);
        assert!(
            state.detail().contains(&password),
            "the generated password is shown once"
        );
    }

    #[test]
    fn a_password_file_is_used_and_not_shown() {
        let fake = Fake::new("console-password-file");
        console(&fake);
        fake.file("/root/admin-password", "correct horse battery staple\n");
        let mut plan = plan(&[Ingest, Console]);
        plan.admin_password_file = Some("/root/admin-password".into());
        let state = run_step(&fake.ctx(&plan), Step::Console);
        assert_eq!(fake.inputs.borrow()[0], "correct horse battery staple\n");
        assert!(!state.detail().contains("correct horse"), "{state:?}");
    }

    #[test]
    fn a_chosen_port_is_listened_on_and_in_the_origin() {
        let fake = Fake::new("console-port");
        console(&fake);
        let mut plan = plan(&[Ingest, Console]);
        plan.console_port = 8443;
        let state = run_step(&fake.ctx(&plan), Step::Console);
        let toml = fake.text("/etc/openvibes/console.toml");
        assert!(
            toml.contains("development_listen = \"0.0.0.0:8443\""),
            "{toml}"
        );
        // Board #72: both IP versions where the kernel binds them together.
        fake.file("/proc/sys/net/ipv6/bindv6only", "0\n");
        run_step(&fake.ctx(&plan), Step::Console);
        let toml = fake.text("/etc/openvibes/console.toml");
        assert!(
            toml.contains("development_listen = \"[::]:8443\""),
            "{toml}"
        );
        assert!(
            fake.called(&["/usr/bin/systemctl", "try-restart", "openvibes-console"]),
            "a running console reads it only on a restart"
        );
        assert!(
            toml.contains("public_origin = \"https://platform.example.com:8443\""),
            "{toml}"
        );
        assert!(
            state
                .detail()
                .starts_with("https://platform.example.com:8443 "),
            "{state:?}"
        );
    }

    #[test]
    fn without_the_console_the_step_is_skipped() {
        let fake = Fake::new("console-skipped");
        assert!(matches!(
            run_step(&fake.ctx(&plan(&[Ingest])), Step::Console),
            StepState::Skipped(_)
        ));
    }

    /// Board #107: with the signer chosen, the console step creates the
    /// site key and version state as the signer's user and lets the console
    /// reach its socket; once both are in place it does neither again.
    #[test]
    fn the_signer_gets_its_key_and_the_console_its_socket_group() {
        let fake = Fake::new("console-signer");
        console(&fake);
        fake.file("/etc/group", "openvibes-signer-clients:x:991:\n");
        let key = "A".repeat(43);
        let trust = format!("site site.key {key}\nsite-alarms site.key {key}\n");
        fake.answer(&["/usr/sbin/runuser", "-u", "openvibes-signer"], 0, &trust);
        fake.answer(
            &[&ADMIN[..], &["rules", "trust", "add"]].concat(),
            0,
            "trusted\n",
        );
        fake.answer(&["/usr/sbin/usermod"], 0, "");
        let plan = plan(&[Ingest, Console, Distribution, Signer]);
        let state = run_step(&fake.ctx(&plan), Step::Console);
        assert!(state.detail().contains("rule signer ready"), "{state:?}");
        assert_eq!(
            fake.call(&["/usr/sbin/runuser", "-u", "openvibes-signer"])[1..],
            [
                "-u",
                "openvibes-signer",
                "-g",
                "openvibes-signer-clients",
                "--",
                "/usr/bin/openvibes-signer",
                "seed",
                "--min-version",
                "1"
            ]
        );
        let added: Vec<String> = fake
            .calls
            .borrow()
            .iter()
            .filter(|call| call[0] == "/usr/sbin/usermod")
            .map(|call| call[3].clone())
            .collect();
        assert_eq!(added, ["openvibes-console", "openvibes-admin"]);
        let trusted: Vec<String> = fake
            .calls
            .borrow()
            .iter()
            .filter(|call| {
                call.get(5..8) == Some(&["rules".into(), "trust".into(), "add".into()][..])
            })
            .map(|call| call[8].clone())
            .collect();
        assert_eq!(
            trusted,
            ["site", "site-alarms"],
            "distribution trusts the key"
        );
        assert_eq!(
            fake.text("/etc/openvibes/site-rules.trust"),
            trust,
            "saved for agent command"
        );

        // Once both are in place, the step finds it done and runs neither.
        let done = Fake::new("console-signer-done");
        done.answer(
            &[&ADMIN[..], &["user", "list"]].concat(),
            0,
            "USERNAME\tSTATUS\nadmin\tactive\n",
        );
        console(&done);
        done.file(
            "/etc/openvibes/console.toml",
            &fake.text("/etc/openvibes/console.toml"),
        );
        done.file(
            "/etc/group",
            "openvibes-signer-clients:x:991:alice,openvibes-console,openvibes-admin\n",
        );
        done.file("/var/lib/openvibes-signer/site.key", "k");
        done.file("/var/lib/openvibes-signer/versions.json", "{}");
        done.file("/etc/openvibes/site-rules.trust", &trust);
        let state = run_step(&done.ctx(&plan), Step::Console);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(!done.called(&["/usr/sbin/runuser", "-u", "openvibes-signer"]));
        assert!(!done.called(&["/usr/sbin/usermod"]));
    }
}
