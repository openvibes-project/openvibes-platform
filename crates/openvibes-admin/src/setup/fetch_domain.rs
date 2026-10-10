//! The console's public host in `/etc/openvibes/fetch.toml`, so the
//! internet fetcher never searches for the platform's own domain.

use platform_host::runner::Runner;

use super::Ctx;

const FETCH_TOML: &str = "/etc/openvibes/fetch.toml";

/// Whether `fetch.toml` names the plan's host, or there is no fetcher.
pub fn set<R: Runner>(ctx: &Ctx<R>) -> Result<bool, String> {
    if !ctx.exists(FETCH_TOML) {
        return Ok(true);
    }
    let table: toml::Table =
        toml::from_str(&ctx.read(FETCH_TOML)?).map_err(|error| format!("{FETCH_TOML}: {error}"))?;
    Ok(table.get("platform_domain").and_then(toml::Value::as_str)
        == Some(ctx.plan.hostname.as_str()))
}

/// Writes `platform_domain` (comments and other keys kept). Each request
/// is a new process, so no restart.
pub fn apply<R: Runner>(ctx: &Ctx<R>) -> Result<(), String> {
    if set(ctx)? {
        return Ok(());
    }
    let mut doc: toml_edit::DocumentMut = ctx
        .read(FETCH_TOML)?
        .parse()
        .map_err(|error| format!("{FETCH_TOML}: {error}"))?;
    doc["platform_domain"] = toml_edit::value(ctx.plan.hostname.as_str());
    ctx.put(
        FETCH_TOML,
        doc.to_string().as_bytes(),
        Some(("root", "openvibes-fetch")),
        0o640,
    )
}

#[cfg(test)]
mod tests {
    use platform_host::{Step, StepState};

    use crate::setup::{
        fake::{Fake, plan},
        plan::Component::*,
        run_step,
    };

    const FETCH: &str = "/etc/openvibes/fetch.toml";

    fn console(fake: &Fake) {
        fake.file(
            "/etc/openvibes/console.toml",
            include_str!("../../../../packaging/rpm/console.toml"),
        );
        fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
        fake.answer(
            &[
                "/usr/sbin/runuser",
                "-u",
                "openvibes-admin",
                "--",
                "/usr/bin/openvibes-admin",
                "user",
                "list",
            ],
            0,
            "USERNAME\tSTATUS\tROLES\tDISPLAY NAME\tLAST SEEN\nadmin\tactive\tadmin\tA\t-\n",
        );
    }

    #[test]
    fn setup_writes_the_platform_domain_into_fetch_toml() {
        let fake = Fake::new("fetch-domain");
        console(&fake);
        fake.file(FETCH, include_str!("../../../../packaging/rpm/fetch.toml"));
        let plan = plan(&[Ingest, Console]);
        let ctx = fake.ctx(&plan);
        let state = run_step(&ctx, Step::Console);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        let text = fake.text(FETCH);
        assert!(
            text.contains("platform_domain = \"platform.example.com\""),
            "{text}"
        );
        assert!(text.contains("database_url = "), "kept: {text}");
        assert!(matches!(
            crate::setup::check(&ctx, Step::Console),
            StepState::Done(_)
        ));
    }

    #[test]
    fn without_the_fetcher_no_fetch_toml_is_made() {
        let fake = Fake::new("fetch-domain-absent");
        console(&fake);
        let state = run_step(&fake.ctx(&plan(&[Ingest, Console])), Step::Console);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(!fake.root.join(FETCH.trim_start_matches('/')).exists());
    }
}
