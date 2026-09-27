//! Step 8: the console's public origin and the first admin account
//! (packaging.md "Console RPM setup"). The TLS files come from step 7.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use platform_host::{Service, StepState, runner::Runner};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use super::{Ctx, plan::Component};
use crate::config_file;

const CONSOLE_TOML: &str = "/etc/openvibes/console.toml";

fn origin<R: Runner>(ctx: &Ctx<R>) -> String {
    format!("https://{}", ctx.plan.hostname)
}

fn origin_set<R: Runner>(ctx: &Ctx<R>) -> Result<bool, String> {
    let table: toml::Table = toml::from_str(&ctx.read(CONSOLE_TOML)?)
        .map_err(|error| format!("{CONSOLE_TOML}: {error}"))?;
    Ok(table.get("public_origin").and_then(toml::Value::as_str) == Some(origin(ctx).as_str()))
}

fn admin_exists<R: Runner>(ctx: &Ctx<R>) -> Result<bool, String> {
    Ok(ctx
        .as_admin(&["user", "list"])?
        .lines()
        .skip(1)
        .any(|line| line.split('\t').next() == Some("admin")))
}

pub fn console_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.plan.has(Component::Console) {
        return Ok(StepState::Skipped("console not chosen".into()));
    }
    Ok(if origin_set(ctx)? && admin_exists(ctx)? {
        StepState::Done(format!("{} · console admin: admin", origin(ctx)))
    } else {
        StepState::Todo
    })
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
        config_file::replace(
            &ctx.path("/etc/openvibes"),
            Service::Console,
            &doc.to_string(),
        )?;
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
    Ok(StepState::Done(format!("{} · {shown}", origin(ctx))))
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
    fn without_the_console_the_step_is_skipped() {
        let fake = Fake::new("console-skipped");
        assert!(matches!(
            run_step(&fake.ctx(&plan(&[Ingest])), Step::Console),
            StepState::Skipped(_)
        ));
    }
}
