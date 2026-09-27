//! Steps 1–2 (and, from Task 4, 3–5): packages, PostgreSQL.

use platform_host::{
    StepState,
    runner::{
        Program::{Dnf, PostgresqlSetup, Rpm, Systemctl, Usermod},
        Runner,
    },
};

use super::{
    Ctx,
    plan::{Component, Plan},
};

/// The platform packages; the rules and agent packages have their own steps.
fn platform_packages(plan: &Plan) -> Vec<&'static str> {
    plan.components
        .iter()
        .filter(|c| !matches!(c, Component::Rules | Component::Agent))
        .flat_map(|c| c.packages())
        .copied()
        .collect()
}

/// The one file for package `name` in `dir` (`NAME-VERSION-….rpm`, not a
/// source package and not `NAME-other-…`).
pub(super) fn local_rpm<R: Runner>(
    ctx: &Ctx<R>,
    dir: &std::path::Path,
    name: &str,
) -> Result<String, String> {
    let prefix = format!("{name}-");
    let shown = dir.display();
    let entries = std::fs::read_dir(ctx.root.join(dir.strip_prefix("/").unwrap_or(dir)))
        .map_err(|error| format!("{shown}: {error}"))?;
    let mut found: Vec<String> = entries
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|file| {
            file.strip_prefix(&prefix)
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
                && file.ends_with(".rpm")
                && !file.ends_with(".src.rpm")
        })
        .collect();
    match found.len() {
        0 => Err(format!("no {name} package in {shown}")),
        1 => Ok(dir.join(found.remove(0)).display().to_string()),
        _ => Err(format!("several {name} packages in {shown}; keep one")),
    }
}

/// `dnf install` from the repository, or the files in `repo_dir`.
pub fn install<R: Runner>(ctx: &Ctx<R>, names: &[&str]) -> Result<(), String> {
    let mut args = vec!["install".to_owned(), "-y".to_owned()];
    match &ctx.plan.repo_dir {
        None => args.extend(names.iter().map(|name| (*name).to_owned())),
        Some(dir) => {
            let check = if ctx.plan.allow_unsigned_local {
                "0"
            } else {
                "1"
            };
            args.push(format!("--setopt=localpkg_gpgcheck={check}"));
            for name in names {
                args.push(local_rpm(ctx, dir, name)?);
            }
        }
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    ctx.ok(Dnf, &args).map(drop)
}

pub fn packages_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let names = platform_packages(ctx.plan);
    let mut args = vec!["-q", "--quiet"];
    args.extend(&names);
    Ok(if ctx.succeeds(Rpm, &args) {
        StepState::Done(format!("installed: {}", names.join(" ")))
    } else {
        StepState::Todo
    })
}

pub fn packages_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let names = platform_packages(ctx.plan);
    install(ctx, &names)?;
    Ok(StepState::Done(format!("installed: {}", names.join(" "))))
}

const PG_VERSION: &str = "/var/lib/pgsql/data/PG_VERSION";

pub fn postgres_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let done = ctx.succeeds(Rpm, &["-q", "--quiet", "postgresql-server"])
        && ctx.exists(PG_VERSION)
        && ctx.succeeds(Systemctl, &["is-active", "--quiet", "postgresql"]);
    Ok(if done {
        StepState::Done("PostgreSQL installed and running".into())
    } else {
        StepState::Todo
    })
}

pub fn postgres_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !ctx.succeeds(Rpm, &["-q", "--quiet", "postgresql-server"]) {
        ctx.ok(Dnf, &["install", "-y", "postgresql-server"])?;
    }
    if !ctx.exists(PG_VERSION) {
        ctx.ok(PostgresqlSetup, &["--initdb"])?;
    }
    ctx.ok(Systemctl, &["enable", "--now", "postgresql"])?;
    Ok(StepState::Done("PostgreSQL installed and running".into()))
}

const OPERATORS: &str = "openvibes-operators";

pub fn operators_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let Some(user) = &ctx.plan.operator else {
        return Ok(StepState::Skipped(
            "no invoking user: Setup was run as root directly".into(),
        ));
    };
    let groups = ctx.read("/etc/group")?;
    let members = groups
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{OPERATORS}:")))
        .ok_or("group openvibes-operators is missing: is openvibes-admin installed?")?
        .rsplit(':')
        .next()
        .unwrap_or("");
    Ok(if members.split(',').any(|member| member == user) {
        StepState::Done(format!("{user} is an operator"))
    } else {
        StepState::Todo
    })
}

pub fn operators_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let Some(user) = &ctx.plan.operator else {
        return operators_check(ctx);
    };
    ctx.ok(Usermod, &["-aG", OPERATORS, user])?;
    Ok(StepState::Done(format!(
        "{user} added to {OPERATORS}; log in again for it to take effect"
    )))
}

fn query<R: Runner>(ctx: &Ctx<R>, sql: &str) -> Result<bool, String> {
    Ok(ctx.as_postgres(&["/usr/bin/psql", "-Atqc", sql])?.trim() == "1")
}

const ROLE: &str = "SELECT 1 FROM pg_roles WHERE rolname = 'openvibes-admin'";
const DATABASE: &str = "SELECT 1 FROM pg_database WHERE datname = 'openvibes'";

pub fn database_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    Ok(if query(ctx, ROLE)? && query(ctx, DATABASE)? {
        StepState::Done("database openvibes owned by openvibes-admin".into())
    } else {
        StepState::Todo
    })
}

pub fn database_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    if !query(ctx, ROLE)? {
        ctx.as_postgres(&["/usr/bin/createuser", "--createrole", "openvibes-admin"])?;
    }
    if !query(ctx, DATABASE)? {
        ctx.as_postgres(&["/usr/bin/createdb", "-O", "openvibes-admin", "openvibes"])?;
    }
    Ok(StepState::Done(
        "database openvibes owned by openvibes-admin".into(),
    ))
}

pub fn schema_check<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    // `status` refuses unless the schema is current.
    Ok(if ctx.as_admin(&["status"]).is_ok() {
        StepState::Done("schema current".into())
    } else {
        StepState::Todo
    })
}

pub fn schema_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let migrated = ctx.as_admin(&["migrate"])?;
    let maintained = ctx.as_admin(&["maintenance"])?;
    Ok(StepState::Done(format!(
        "{}; {}",
        migrated.trim(),
        maintained.trim()
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

    #[test]
    fn packages_are_installed_from_the_repository() {
        let fake = Fake::new("packages-repo");
        fake.answer(&["/usr/bin/rpm"], 1, "");
        fake.answer(&["/usr/bin/dnf", "install"], 0, "");
        let plan = plan(&[Ingest, Console, Vulns, Rules, Agent, Distribution]);
        let state = run_step(&fake.ctx(&plan), Step::Packages);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert_eq!(
            fake.call(&["/usr/bin/dnf"]),
            [
                "/usr/bin/dnf",
                "install",
                "-y",
                "openvibes-ingest",
                "openvibes-admin",
                "openvibes-console",
                "openvibes-distribution",
                "openvibes-vulns"
            ]
        );
    }

    #[test]
    fn a_done_step_is_not_run_again() {
        let fake = Fake::new("packages-done");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet"], 0, "");
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Packages);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(!fake.called(&["/usr/bin/dnf"]));
    }

    #[test]
    fn local_packages_pick_the_exact_name_and_refuse_duplicates() {
        let fake = Fake::new("packages-local");
        for file in [
            "openvibes-ingest-0.1.0-1.fc44.x86_64.rpm",
            "openvibes-admin-0.1.0-1.fc44.x86_64.rpm",
            "openvibes-llm-0.1.0-1.fc44.x86_64.rpm",
            "openvibes-llm-vulkan-0.1.0-1.fc44.x86_64.rpm",
            "openvibes-ingest-0.1.0-1.fc44.src.rpm",
        ] {
            fake.file(&format!("/srv/rpms/{file}"), "");
        }
        fake.answer(&["/usr/bin/rpm"], 1, "");
        fake.answer(&["/usr/bin/dnf", "install"], 0, "");
        let mut plan = plan(&[Ingest, Assistant]);
        plan.repo_dir = Some("/srv/rpms".into());
        assert!(matches!(
            run_step(&fake.ctx(&plan), Step::Packages),
            StepState::Done(_)
        ));
        assert_eq!(
            fake.call(&["/usr/bin/dnf"]),
            [
                "/usr/bin/dnf",
                "install",
                "-y",
                "--setopt=localpkg_gpgcheck=1",
                "/srv/rpms/openvibes-ingest-0.1.0-1.fc44.x86_64.rpm",
                "/srv/rpms/openvibes-admin-0.1.0-1.fc44.x86_64.rpm",
                "/srv/rpms/openvibes-llm-0.1.0-1.fc44.x86_64.rpm"
            ]
        );

        plan.allow_unsigned_local = true;
        fake.calls.borrow_mut().clear();
        run_step(&fake.ctx(&plan), Step::Packages);
        assert_eq!(
            fake.call(&["/usr/bin/dnf"])[3],
            "--setopt=localpkg_gpgcheck=0"
        );

        fake.file("/srv/rpms/openvibes-ingest-0.2.0-1.fc44.x86_64.rpm", "");
        let state = run_step(&fake.ctx(&plan), Step::Packages);
        assert!(
            state
                .detail()
                .contains("several openvibes-ingest packages in /srv/rpms"),
            "{state:?}"
        );

        plan.components.push(Console);
        std::fs::remove_file(
            fake.root
                .join("srv/rpms/openvibes-ingest-0.2.0-1.fc44.x86_64.rpm"),
        )
        .unwrap();
        let state = run_step(&fake.ctx(&plan), Step::Packages);
        assert!(
            state
                .detail()
                .contains("no openvibes-console package in /srv/rpms"),
            "{state:?}"
        );
    }

    #[test]
    fn postgres_is_installed_initialised_and_started() {
        let fake = Fake::new("postgres");
        fake.answer(
            &["/usr/bin/rpm", "-q", "--quiet", "postgresql-server"],
            1,
            "",
        );
        fake.answer(
            &["/usr/bin/dnf", "install", "-y", "postgresql-server"],
            0,
            "",
        );
        fake.effect(&["/usr/bin/postgresql-setup", "--initdb"], |root| {
            std::fs::create_dir_all(root.join("var/lib/pgsql/data")).unwrap();
            std::fs::write(root.join("var/lib/pgsql/data/PG_VERSION"), "17\n").unwrap();
        });
        fake.answer(&["/usr/bin/systemctl", "is-active"], 3, "");
        fake.answer(
            &["/usr/bin/systemctl", "enable", "--now", "postgresql"],
            0,
            "",
        );
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Postgres);
        assert_eq!(
            state,
            StepState::Done("PostgreSQL installed and running".into())
        );
        assert!(fake.root.join("var/lib/pgsql/data/PG_VERSION").exists());
    }
    #[test]
    fn the_invoking_user_joins_the_operators() {
        let fake = Fake::new("operators");
        fake.answer(
            &["/usr/sbin/usermod", "-aG", "openvibes-operators", "alice"],
            0,
            "",
        );
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Operators);
        assert!(state.detail().contains("log in again"), "{state:?}");
        assert!(fake.called(&["/usr/sbin/usermod"]));

        let fake = Fake::new("operators-member");
        fake.file("/etc/group", "openvibes-operators:x:990:bob,alice\n");
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Operators);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(!fake.called(&["/usr/sbin/usermod"]));

        let mut as_root = plan(&[Ingest]);
        as_root.operator = None;
        assert!(matches!(
            run_step(&fake.ctx(&as_root), Step::Operators),
            StepState::Skipped(_)
        ));
    }

    #[test]
    fn the_database_and_role_are_created_only_when_missing() {
        let fake = Fake::new("database");
        let psql = [
            "/usr/sbin/runuser",
            "-u",
            "postgres",
            "--",
            "/usr/bin/psql",
            "-Atqc",
        ];
        fake.answer(
            &[
                &psql[..],
                &["SELECT 1 FROM pg_roles WHERE rolname = 'openvibes-admin'"],
            ]
            .concat(),
            0,
            "1\n",
        );
        fake.answer(
            &[
                &psql[..],
                &["SELECT 1 FROM pg_database WHERE datname = 'openvibes'"],
            ]
            .concat(),
            0,
            "",
        );
        fake.answer(
            &[
                "/usr/sbin/runuser",
                "-u",
                "postgres",
                "--",
                "/usr/bin/createdb",
                "-O",
                "openvibes-admin",
                "openvibes",
            ],
            0,
            "",
        );
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Database);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert!(!fake.called(&[
            "/usr/sbin/runuser",
            "-u",
            "postgres",
            "--",
            "/usr/bin/createuser"
        ]));
        assert!(fake.called(&[
            "/usr/sbin/runuser",
            "-u",
            "postgres",
            "--",
            "/usr/bin/createdb"
        ]));
    }

    #[test]
    fn the_schema_is_migrated_and_partitions_created() {
        let fake = Fake::new("schema");
        let admin = [
            "/usr/sbin/runuser",
            "-u",
            "openvibes-admin",
            "--",
            "/usr/bin/openvibes-admin",
        ];
        fake.answer(&[&admin[..], &["status"]].concat(), 1, "");
        fake.answer(
            &[&admin[..], &["migrate"]].concat(),
            0,
            "schema version 24\n",
        );
        fake.answer(
            &[&admin[..], &["maintenance"]].concat(),
            0,
            "created 97 partitions\n",
        );
        let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Schema);
        assert_eq!(
            state,
            StepState::Done("schema version 24; created 97 partitions".into())
        );
    }
}
