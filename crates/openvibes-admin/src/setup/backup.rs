//! The database backup Update and Remove everything offer first (§6.5,
//! §6.5a): `pg_dump` into a directory only postgres can write, checked with
//! `pg_restore --list`, then handed to the user as a new 0600 file, with the
//! roles next to it. Nothing is ever written over an existing file.

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use platform_host::runner::Runner;

use super::Ctx;

const WORK: &str = "/var/tmp/openvibes-backup";
const DUMP: &str = "/var/tmp/openvibes-backup/openvibes.dump";

pub fn dump<R: Runner>(ctx: &Ctx<R>, out: &Path) -> Result<String, String> {
    let shown = out.display().to_string();
    let roles_file = format!("{shown}.roles.sql");
    for file in [&shown, &roles_file] {
        if ctx.exists(file) {
            return Err(format!("{file} already exists; choose another backup file"));
        }
    }
    let work = ctx.path(WORK);
    if work.exists() {
        fs::remove_dir_all(&work).map_err(|error| format!("{WORK}: {error}"))?;
    }
    fs::create_dir_all(&work).map_err(|error| format!("{WORK}: {error}"))?;
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("{WORK}: {error}"))?;
    ctx.chown(WORK, Some(("postgres", "postgres")))?;
    let result = (|| {
        ctx.as_postgres(&[
            "/usr/bin/pg_dump",
            "--format=custom",
            "--file",
            DUMP,
            "openvibes",
        ])?;
        let roles =
            ctx.as_postgres(&["/usr/bin/pg_dumpall", "--roles-only", "--no-role-passwords"])?;
        ctx.as_postgres(&["/usr/bin/pg_restore", "--list", DUMP])?;
        let size = fs::metadata(ctx.path(DUMP))
            .map_err(|error| format!("{DUMP}: {error}"))?
            .len();
        if size == 0 {
            return Err("the database dump is empty".to_owned());
        }
        let mut dump =
            fs::File::open(ctx.path(DUMP)).map_err(|error| format!("{DUMP}: {error}"))?;
        let note = ctx.write_new(&shown, &mut dump)?;
        ctx.write_new(&roles_file, &mut roles.as_bytes())?;
        Ok(format!(
            "backup saved to {shown} ({size} bytes) and {roles_file}{note}"
        ))
    })();
    let _ = fs::remove_dir_all(&work);
    result
}

#[cfg(test)]
mod tests {
    use crate::setup::fake::{Fake, plan};
    use crate::setup::plan::Component::*;

    const PG: [&str; 4] = ["/usr/sbin/runuser", "-u", "postgres", "--"];

    fn postgres(fake: &Fake) {
        fake.effect(&[&PG[..], &["/usr/bin/pg_dump"]].concat(), |root| {
            std::fs::write(
                root.join("var/tmp/openvibes-backup/openvibes.dump"),
                "PGDMP data",
            )
            .unwrap();
        });
        fake.answer(
            &[&PG[..], &["/usr/bin/pg_dumpall"]].concat(),
            0,
            "CREATE ROLE \"openvibes-admin\";\n",
        );
        fake.answer(
            &[&PG[..], &["/usr/bin/pg_restore", "--list"]].concat(),
            0,
            "; Archive created\n",
        );
    }

    #[test]
    fn a_backup_is_dumped_checked_and_handed_over() {
        let fake = Fake::new("backup");
        postgres(&fake);
        std::fs::create_dir_all(fake.root.join("home/alice")).unwrap();
        let plan = plan(&[Ingest]);
        let note =
            super::dump(&fake.ctx(&plan), std::path::Path::new("/home/alice/b.dump")).unwrap();
        assert!(note.contains("/home/alice/b.dump"), "{note}");
        assert_eq!(fake.text("/home/alice/b.dump"), "PGDMP data");
        assert!(
            fake.text("/home/alice/b.dump.roles.sql")
                .contains("CREATE ROLE")
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(fake.root.join("home/alice/b.dump"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(
            !fake.root.join("var/tmp/openvibes-backup").exists(),
            "staging removed"
        );
        let dumpall = fake.call(&[&PG[..], &["/usr/bin/pg_dumpall"]].concat());
        assert!(
            dumpall.contains(&"--no-role-passwords".to_owned()),
            "{dumpall:?}"
        );
    }

    #[test]
    fn an_existing_backup_file_is_not_overwritten() {
        let fake = Fake::new("backup-exists");
        postgres(&fake);
        fake.file("/home/alice/b.dump", "last month");
        let plan = plan(&[Ingest]);
        let error =
            super::dump(&fake.ctx(&plan), std::path::Path::new("/home/alice/b.dump")).unwrap_err();
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(fake.text("/home/alice/b.dump"), "last month");
        assert!(!fake.called(&[&PG[..], &["/usr/bin/pg_dump"]].concat()));
    }

    #[test]
    fn an_unreadable_dump_is_not_handed_over() {
        let fake = Fake::new("backup-bad");
        fake.effect(&[&PG[..], &["/usr/bin/pg_dump"]].concat(), |root| {
            std::fs::write(root.join("var/tmp/openvibes-backup/openvibes.dump"), "").unwrap();
        });
        fake.answer(&[&PG[..], &["/usr/bin/pg_dumpall"]].concat(), 0, "");
        fake.answer(&[&PG[..], &["/usr/bin/pg_restore"]].concat(), 1, "");
        std::fs::create_dir_all(fake.root.join("home/alice")).unwrap();
        let plan = plan(&[Ingest]);
        assert!(super::dump(&fake.ctx(&plan), std::path::Path::new("/home/alice/b.dump")).is_err());
        assert!(!fake.root.join("home/alice/b.dump").exists());
    }
}
