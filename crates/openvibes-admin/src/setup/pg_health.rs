//! PostgreSQL health for Update and Remove (#292): the server removed or
//! stopped by hand is put back; a lost or newer-than-data cluster is
//! refused, never initialised over.

use platform_host::runner::{
    Program::{Rpm, Systemctl},
    Runner,
};

use super::{
    Ctx,
    base::{PG_RECORD, PG_VERSION, postgres_apply},
};

const NOT_INSTALLED: &str = "PostgreSQL is not installed (postgresql-server is missing)";
const GONE: &str = "the PostgreSQL data folder /var/lib/pgsql/data is gone";

/// The text before the first `.`, trimmed.
fn major(version: &str) -> &str {
    version.trim().split('.').next().unwrap_or("")
}

/// The data and server majors when they differ (server installed, cluster present).
fn mismatch<R: Runner>(ctx: &Ctx<R>) -> Option<String> {
    let server = ctx
        .stdout(Rpm, &["-q", "--qf", "%{VERSION}", "postgresql-server"])
        .ok()?;
    let data = ctx.read(PG_VERSION).ok()?;
    let (data, server) = (data.trim(), major(&server));
    (data != server).then(|| {
        format!(
            "the database was made by PostgreSQL {data} and the installed server is {server}: upgrade the data with postgresql-setup --upgrade"
        )
    })
}

/// Why PostgreSQL is not healthy, or `None`.
pub(super) fn problem<R: Runner>(ctx: &Ctx<R>) -> Option<String> {
    if !ctx.succeeds(Rpm, &["-q", "--quiet", "postgresql-server"]) {
        return Some(NOT_INSTALLED.into());
    }
    if !ctx.exists(PG_VERSION) {
        return Some(GONE.into());
    }
    if let Some(text) = mismatch(ctx) {
        return Some(text);
    }
    (!ctx.succeeds(Systemctl, &["is-active", "--quiet", "postgresql"]))
        .then(|| "PostgreSQL is not running".into())
}

/// Puts back a removed or stopped server. A gone cluster or a version
/// difference is an `Err`: initialising would hide the lost data.
pub(super) fn ensure<R: Runner>(ctx: &Ctx<R>) -> Result<Option<String>, String> {
    if !ctx.exists(PG_VERSION) {
        return Err(GONE.into());
    }
    let Some(found) = problem(ctx) else {
        return Ok(None);
    };
    if found.starts_with("the database was made") {
        return Err(found);
    }
    // Setup's record is left exactly as found: a PostgreSQL the user put
    // back themselves must not become Remove everything's to remove.
    let record = ctx.read(PG_RECORD).ok();
    let applied = postgres_apply(ctx);
    match &record {
        None => {
            let _ = std::fs::remove_file(ctx.path(PG_RECORD));
        }
        Some(old) => ctx.put(PG_RECORD, old.as_bytes(), None, 0o644)?,
    }
    // A newer server refuses the old cluster, so its start fails too: say why.
    applied.map_err(|error| mismatch(ctx).unwrap_or_else(|| format!("{found}: {error}")))?;
    if let Some(text) = mismatch(ctx) {
        return Err(text);
    }
    Ok(Some(
        "PostgreSQL was missing or stopped: installed and started it again".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::fake::{Fake, plan};

    const RPM_Q: &[&str] = &["/usr/bin/rpm", "-q", "--quiet", "postgresql-server"];
    const RPM_V: &[&str] = &["/usr/bin/rpm", "-q", "--qf"];
    const ACTIVE: &[&str] = &["/usr/bin/systemctl", "is-active"];

    fn fake(test: &str, data: Option<&str>) -> Fake {
        let fake = Fake::new(test);
        if let Some(data) = data {
            fake.file(PG_VERSION, data);
        }
        fake
    }

    /// The fallbacks (first answer wins): installed, active, version 18.6.
    fn rest(fake: &Fake) {
        fake.answer(RPM_V, 0, "18.6");
        fake.answer(RPM_Q, 0, "");
        fake.answer(ACTIVE, 0, "");
        fake.answer(&["/usr/bin/dnf"], 0, "");
        fake.answer(&["/usr/bin/systemctl", "enable"], 0, "");
    }

    #[test]
    fn a_healthy_server_has_no_problem() {
        let fake = fake("pgh-healthy", Some("18\n"));
        rest(&fake);
        let plan = plan(&[]);
        let ctx = fake.ctx(&plan);
        assert_eq!(problem(&ctx), None);
        assert_eq!(ensure(&ctx), Ok(None));
        assert!(!fake.called(&["/usr/bin/dnf"]));
    }

    #[test]
    fn a_removed_server_is_installed_and_started() {
        let fake = fake("pgh-removed", Some("18\n"));
        fake.answer(RPM_Q, 1, "");
        rest(&fake);
        let plan = plan(&[]);
        let ctx = fake.ctx(&plan);
        assert_eq!(problem(&ctx).as_deref(), Some(NOT_INSTALLED));
        assert!(matches!(ensure(&ctx), Ok(Some(_))));
        fake.call(&["/usr/bin/dnf", "install", "-y", "postgresql-server"]);
        fake.call(&["/usr/bin/systemctl", "enable", "--now", "postgresql"]);
        assert!(!fake.called(&["/usr/bin/postgresql-setup"]));
    }

    #[test]
    fn a_stopped_server_is_started() {
        let fake = fake("pgh-stopped", Some("18\n"));
        fake.answer(ACTIVE, 3, "");
        rest(&fake);
        let plan = plan(&[]);
        let ctx = fake.ctx(&plan);
        assert_eq!(problem(&ctx).as_deref(), Some("PostgreSQL is not running"));
        assert!(matches!(ensure(&ctx), Ok(Some(_))));
        fake.call(&["/usr/bin/systemctl", "enable", "--now", "postgresql"]);
        assert!(!fake.called(&["/usr/bin/dnf"]));
    }

    #[test]
    fn no_cluster_is_refused_never_initialised() {
        let fake = fake("pgh-nocluster", None);
        rest(&fake);
        let plan = plan(&[]);
        let error = ensure(&fake.ctx(&plan)).unwrap_err();
        assert!(
            error.contains("data folder /var/lib/pgsql/data is gone"),
            "{error}"
        );
        assert!(!fake.called(&["/usr/bin/dnf"]));
        assert!(!fake.called(&["/usr/bin/postgresql-setup"]));
    }

    #[test]
    fn a_newer_server_than_the_data_is_refused() {
        let fake = fake("pgh-newer", Some("18\n"));
        fake.answer(RPM_V, 0, "19.1");
        rest(&fake);
        let plan = plan(&[]);
        let error = ensure(&fake.ctx(&plan)).unwrap_err();
        assert!(
            error.contains("made by PostgreSQL 18 and the installed server is 19"),
            "{error}"
        );
        assert!(!fake.called(&["/usr/bin/systemctl", "enable"]));
    }

    const MADE_BY_18: &str = "made by PostgreSQL 18 and the installed server is 19";
    const RECORD: &str = "/etc/openvibes/setup-installed-postgresql";

    #[test]
    fn a_failed_start_after_installing_a_newer_server_says_why() {
        let fake = fake("pgh-newer-start", Some("18\n"));
        fake.answer(RPM_Q, 1, "");
        fake.answer(RPM_V, 0, "19.1");
        fake.fail(&["/usr/bin/systemctl", "enable"], "refuses the old cluster");
        rest(&fake);
        let plan = plan(&[]);
        let error = ensure(&fake.ctx(&plan)).unwrap_err();
        assert!(error.contains(MADE_BY_18), "{error}");
    }

    #[test]
    fn a_newer_server_installed_by_the_put_back_is_refused() {
        let fake = fake("pgh-newer-installed", Some("18\n"));
        fake.answer(RPM_Q, 1, "");
        fake.answer(RPM_V, 0, "19.1");
        rest(&fake);
        let plan = plan(&[]);
        let error = ensure(&fake.ctx(&plan)).unwrap_err();
        assert!(error.contains(MADE_BY_18), "{error}");
    }

    #[test]
    fn the_put_back_leaves_no_record_where_there_was_none() {
        let fake = fake("pgh-norecord", Some("18\n"));
        fake.answer(RPM_Q, 1, "");
        rest(&fake);
        let plan = plan(&[]);
        assert!(matches!(ensure(&fake.ctx(&plan)), Ok(Some(_))));
        assert!(!fake.root.join(RECORD.trim_start_matches('/')).exists());
    }

    #[test]
    fn the_put_back_keeps_an_existing_record_as_it_was() {
        let fake = fake("pgh-record", Some("18\n"));
        fake.file(RECORD, "postgresql-server\n");
        fake.answer(RPM_Q, 1, "");
        rest(&fake);
        let plan = plan(&[]);
        assert!(matches!(ensure(&fake.ctx(&plan)), Ok(Some(_))));
        assert_eq!(fake.text(RECORD), "postgresql-server\n");
    }
}
