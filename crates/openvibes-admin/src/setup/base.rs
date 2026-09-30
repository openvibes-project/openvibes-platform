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
    dnf(ctx, "install", names)
}

fn dnf<R: Runner>(ctx: &Ctx<R>, verb: &str, names: &[&str]) -> Result<(), String> {
    let mut args = vec![verb.to_owned(), "-y".to_owned()];
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
    Ok(
        if ctx.succeeds(Rpm, &args) && missing_config(ctx, &names).is_empty() {
            StepState::Done(format!("installed: {}", names.join(" ")))
        } else {
            StepState::Todo
        },
    )
}

pub fn packages_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let names = platform_packages(ctx.plan);
    install(ctx, &names)?;
    // #82: a configuration file deleted while its package stayed installed
    // (an interrupted Remove everything) is not put back by `install`;
    // `reinstall` restores it and leaves edited ones alone.
    let missing = missing_config(ctx, &names);
    if !missing.is_empty() {
        dnf(ctx, "reinstall", &missing)?;
    }
    Ok(StepState::Done(format!("installed: {}", names.join(" "))))
}

/// The installed `names` whose packaged configuration file is missing
/// (`rpm -V` marks it `missing  c /path`).
fn missing_config<'n, R: Runner>(ctx: &Ctx<R>, names: &[&'n str]) -> Vec<&'n str> {
    names
        .iter()
        .copied()
        .filter(|name| {
            ctx.stdout(
                Rpm,
                &["-V", "--nodeps", "--nodigest", "--nosignature", name],
            )
            .is_ok_and(|out| {
                out.lines().any(|line| {
                    let mut words = line.split_whitespace();
                    words.next() == Some("missing") && words.next() == Some("c")
                })
            })
        })
        .collect()
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
    // `status` refuses unless the schema is current, and says when the
    // pending change needs Update's backup (board #77): Check and Repair
    // report that instead of migrating.
    Ok(match ctx.as_admin(&["status"]) {
        Ok(_) => StepState::Done("schema current".into()),
        Err(error) if error.contains("changes stored data") => StepState::Failed(error),
        Err(_) => StepState::Todo,
    })
}

pub fn schema_apply<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    // A first install has no data to lose; Repair never migrates past a
    // change to stored data without Update's backup.
    let args: &[&str] = if ctx.repair {
        &["migrate", "--additive"]
    } else {
        &["migrate"]
    };
    let migrated = ctx.as_admin(args)?;
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

    /// #82: Setup after an interrupted Remove everything finds admin.toml
    /// gone while the package is installed, and reinstalls that package.
    #[test]
    fn a_missing_config_file_is_restored_by_a_reinstall() {
        let fake = Fake::new("packages-config");
        fake.answer(&["/usr/bin/rpm", "-q", "--quiet"], 0, "");
        fake.answer(
            &[
                "/usr/bin/rpm",
                "-V",
                "--nodeps",
                "--nodigest",
                "--nosignature",
                "openvibes-admin",
            ],
            1,
            "missing   c /etc/openvibes/admin.toml\n",
        );
        fake.answer(
            &["/usr/bin/rpm", "-V"],
            1,
            "S.5....T.  c /etc/openvibes/ingest.toml\n",
        );
        fake.answer(&["/usr/bin/dnf"], 0, "");
        let plan = plan(&[Ingest]);
        let ctx = fake.ctx(&plan);
        assert_eq!(
            super::super::check(&ctx, Step::Packages),
            StepState::Todo,
            "an edited config is fine, a missing one is not"
        );
        let state = run_step(&ctx, Step::Packages);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        assert_eq!(
            fake.call(&["/usr/bin/dnf", "reinstall"]),
            ["/usr/bin/dnf", "reinstall", "-y", "openvibes-admin"]
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

    const ADMIN: [&str; 5] = [
        "/usr/sbin/runuser",
        "-u",
        "openvibes-admin",
        "--",
        "/usr/bin/openvibes-admin",
    ];

    fn admin(rest: &[&'static str]) -> Vec<&'static str> {
        ADMIN.iter().chain(rest).copied().collect()
    }

    /// Board #77: Check and Repair report a pending change to stored data
    /// and leave it to Update, which backs up first.
    #[test]
    fn a_schema_change_to_stored_data_waits_for_update() {
        let fake = Fake::new("schema-needs-backup");
        fake.fail(
            &admin(&["status"]),
            "openvibes-admin: this upgrade changes stored data (migration 29): run \
             `openvibes-admin` → Update",
        );
        let plan = plan(&[Ingest]);
        let mut ctx = fake.ctx(&plan);
        ctx.repair = true;
        let state = run_step(&ctx, Step::Schema);
        assert!(
            matches!(&state, StepState::Failed(text) if text.contains("Update")),
            "{state:?}"
        );
        assert!(!fake.called(&admin(&["migrate"])));
    }

    #[test]
    fn repair_migrates_only_additively() {
        let fake = Fake::new("schema-repair");
        fake.answer(&admin(&["status"]), 1, "schema is not current");
        fake.answer(&admin(&["migrate"]), 0, "schema version 28\n");
        fake.answer(&admin(&["maintenance"]), 0, "ok\n");
        let plan = plan(&[Ingest]);
        let mut ctx = fake.ctx(&plan);
        ctx.repair = true;
        run_step(&ctx, Step::Schema);
        assert_eq!(fake.call(&admin(&["migrate"]))[6..], ["--additive"]);
        let fake = Fake::new("schema-install");
        fake.answer(&admin(&["status"]), 1, "no schema");
        fake.answer(&admin(&["migrate"]), 0, "schema version 28\n");
        fake.answer(&admin(&["maintenance"]), 0, "ok\n");
        run_step(&fake.ctx(&plan), Step::Schema);
        assert_eq!(
            fake.call(&admin(&["migrate"])).len(),
            6,
            "a first install migrates fully"
        );
    }
}
