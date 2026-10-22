//! Remove everything's PostgreSQL removal: only what Setup installed, and
//! only when nothing else uses it. Split from `remove.rs` (size).

use platform_host::runner::{
    Program::{Rpm, Systemctl},
    Runner,
};

use super::{
    super::base::{PG_MARK, PG_PACKAGES, PG_RECORD},
    Ctx, installed, remove_file_or_dir,
};

const TABLES: &str = "SELECT count(*) FROM pg_catalog.pg_tables \
                      WHERE schemaname NOT IN ('pg_catalog','information_schema')";

/// PostgreSQL goes only when Setup installed it (the record), the package
/// is still installed and the cluster holds nothing but the system
/// databases and `openvibes`, and no user table in `postgres`. Everything
/// that can refuse runs before the mark and before anything stops; after the
/// mark, each part checks whether it is still to do, so a retry finishes. `/var/lib/pgsql` goes only under
/// the mark, never on a record alone. The record goes last.
pub(super) fn postgresql<R: Runner>(ctx: &Ctx<R>) -> Result<String, String> {
    let Ok(record) = ctx.read(PG_RECORD) else {
        return Ok("Setup has no record of installing PostgreSQL; it stays".into());
    };
    let others = ctx.as_postgres(&[
        "/usr/bin/psql",
        "-Atqc",
        "SELECT datname FROM pg_database WHERE datname NOT IN ('postgres','template0','template1','openvibes')",
    ]);
    // The mark is trusted only while the cluster does not answer: a stale
    // one (Setup took PostgreSQL back) must never skip the checks (review I2).
    if !ctx.exists(PG_MARK) || others.is_ok() {
        if !installed(ctx, "postgresql-server") {
            remove_file_or_dir(&ctx.path(PG_RECORD))?;
            return Ok(
                "the record of Setup installing PostgreSQL was stale, so PostgreSQL is not removed"
                    .into(),
            );
        }
        let count = others?.lines().filter(|l| !l.trim().is_empty()).count();
        // User tables in the `postgres` database itself are data too.
        let tables = ctx.as_postgres(&["/usr/bin/psql", "-d", "postgres", "-Atqc", TABLES])?;
        let tables: usize = (tables.trim().parse())
            .map_err(|_| format!("the postgres database's tables were not counted: {tables:?}"))?;
        let held: Vec<String> = [
            (count, format!("it holds {count} other database")),
            (
                tables,
                format!("the postgres database holds {tables} table"),
            ),
        ]
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, text)| format!("{text}{}", if n == 1 { "" } else { "s" }))
        .collect();
        let mut test = vec!["-e", "--test"];
        test.extend(packages_to_remove(ctx, &record));
        let stays = if !held.is_empty() {
            Some(format!("PostgreSQL stays: {}", held.join(" and ")))
        } else {
            // Another package needs it (review I1): it stays, Purge finishes.
            ctx.ok(Rpm, &test)
                .err()
                .map(|why| format!("PostgreSQL stays: other packages need it ({why})"))
        };
        if let Some(stays) = stays {
            remove_file_or_dir(&ctx.path(PG_MARK))?;
            return Ok(stays);
        }
        ctx.put(PG_MARK, b"removing\n", None, 0o644)?;
    }
    if installed(ctx, "postgresql-server") {
        ctx.ok(Systemctl, &["disable", "--now", "postgresql"])?;
        let mut argv = vec!["-e"];
        argv.extend(packages_to_remove(ctx, &record));
        ctx.ok(Rpm, &argv)?;
    }
    remove_file_or_dir(&ctx.path("/var/lib/pgsql"))?;
    remove_file_or_dir(&ctx.path(PG_MARK))?;
    remove_file_or_dir(&ctx.path(PG_RECORD))?;
    Ok("PostgreSQL removed: Setup installed it and nothing else uses it".into())
}

fn packages_to_remove<'a, R: Runner>(ctx: &Ctx<R>, record: &'a str) -> Vec<&'a str> {
    record
        .lines()
        .filter(|p| PG_PACKAGES.contains(p) && installed(ctx, p))
        .collect()
}
