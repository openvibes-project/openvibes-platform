//! The database backup Update and Remove everything offer first (§6.5,
//! §6.5a): `pg_dump` into a directory only postgres can write, checked with
//! `pg_restore --list`, then handed to the user as a new 0600 file, with the
//! roles next to it. Nothing is ever written over an existing file.

use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Component, Path},
};

use platform_host::runner::Runner;
use ring::rand::{SecureRandom, SystemRandom};

use super::Ctx;

/// The TUI's backup choices (world-readable: one folder, one flag);
/// Remove everything deletes it with /etc/openvibes.
pub const MEMORY: &str = "/etc/openvibes/backup.toml";

/// Records the folder of a backup just written and, when given, whether
/// the operator backs up first (Update's and Uninstall's Back up first).
pub fn remember<R: Runner>(
    ctx: &Ctx<R>,
    folder: Option<&Path>,
    first: Option<bool>,
) -> Result<(), String> {
    let mut doc: toml_edit::DocumentMut = ctx
        .read(MEMORY)
        .unwrap_or_default()
        .parse()
        .unwrap_or_default();
    if let Some(folder) = folder.and_then(Path::to_str) {
        doc["folder"] = toml_edit::value(folder);
    }
    if let Some(first) = first {
        doc["first"] = toml_edit::value(first);
    }
    ctx.put(MEMORY, doc.to_string().as_bytes(), None, 0o644)
}

/// The trust boundary for a path the root helper writes to: absolute and
/// free of `..` (checked when the arguments are read).
pub fn check_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{} is not an absolute path", path.display()));
    }
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(format!("{} contains ..", path.display()));
    }
    Ok(())
}

/// A new directory for postgres to dump into: a random name in /var/tmp
/// (on disk, not in RAM), made with mkdir, which fails on anything already
/// there and never follows a symlink. /var/tmp is sticky, so nobody else can
/// replace the directory once it is ours.
fn staging<R: Runner>(ctx: &Ctx<R>) -> Result<String, String> {
    let mut bytes = [0_u8; 8];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "could not pick a staging directory name".to_owned())?;
    let name: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let work = format!("/var/tmp/openvibes-backup-{name}");
    let parent = ctx.path("/var/tmp");
    fs::create_dir_all(&parent).map_err(|error| format!("/var/tmp: {error}"))?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(ctx.path(&work))
        .map_err(|error| format!("{work}: {error}"))?;
    ctx.chown(&work, Some(("postgres", "postgres")))?;
    Ok(work)
}

pub fn dump<R: Runner>(ctx: &Ctx<R>, out: &Path) -> Result<String, String> {
    check_path(out)?;
    let shown = out.display().to_string();
    let folder = out.parent().ok_or_else(|| format!("{shown}: no folder"))?;
    if !ctx.path(&folder.display().to_string()).is_dir() {
        return Err(format!("{} is not a folder", folder.display()));
    }
    // The root helper writes here: a symbolic link anywhere in the path
    // could be swapped for another target after this check, so none is
    // accepted (the real path is always available to the caller).
    let real = fs::canonicalize(ctx.root)
        .map_err(|error| format!("{}: {error}", ctx.root.display()))?
        .join(folder.strip_prefix("/").unwrap_or(folder));
    if fs::canonicalize(ctx.path(&folder.display().to_string()))
        .ok()
        .as_deref()
        != Some(&real)
    {
        return Err(format!(
            "{} goes through a symbolic link: give the folder's real path",
            folder.display()
        ));
    }
    let roles_file = format!("{shown}.roles.sql");
    for file in [&shown, &roles_file] {
        if ctx.exists(file) {
            return Err(format!("{file} already exists; choose another backup file"));
        }
    }
    let work = staging(ctx)?;
    let dump_file = format!("{work}/openvibes.dump");
    let dump_file = dump_file.as_str();
    let result = (|| {
        ctx.as_postgres(&[
            "/usr/bin/pg_dump",
            "--format=custom",
            "--file",
            dump_file,
            "openvibes",
        ])?;
        let roles =
            ctx.as_postgres(&["/usr/bin/pg_dumpall", "--roles-only", "--no-role-passwords"])?;
        ctx.as_postgres(&["/usr/bin/pg_restore", "--list", dump_file])?;
        let size = fs::metadata(ctx.path(dump_file))
            .map_err(|error| format!("{dump_file}: {error}"))?
            .len();
        if size == 0 {
            return Err("the database dump is empty".to_owned());
        }
        let mut dump =
            fs::File::open(ctx.path(dump_file)).map_err(|error| format!("{dump_file}: {error}"))?;
        let note = ctx.write_new(&shown, &mut dump)?;
        // No orphan: a dump without its roles is not what was promised.
        if let Err(error) = ctx.write_new(&roles_file, &mut roles.as_bytes()) {
            let _ = fs::remove_file(ctx.path(&shown));
            return Err(error);
        }
        // A convenience for the next time: a failure here never fails the backup.
        let kept = match remember(ctx, Some(folder), None) {
            Ok(()) => String::new(),
            Err(error) => format!(" (the folder is not remembered: {error})"),
        };
        Ok(format!(
            "backup saved to {shown} ({size} bytes) and {roles_file}{note}{kept}"
        ))
    })();
    let _ = fs::remove_dir_all(ctx.path(&work));
    result
}

#[cfg(test)]
mod tests {
    use crate::setup::fake::{Fake, plan};
    use crate::setup::plan::Component::*;

    const PG: [&str; 4] = ["/usr/sbin/runuser", "-u", "postgres", "--"];

    /// The staging directory the dump created under var/tmp.
    fn staging(root: &std::path::Path) -> std::path::PathBuf {
        std::fs::read_dir(root.join("var/tmp"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("openvibes-backup-"))
            })
            .expect("a fresh staging directory")
    }

    fn postgres(fake: &Fake) {
        fake.effect(&[&PG[..], &["/usr/bin/pg_dump"]].concat(), |root| {
            std::fs::write(staging(root).join("openvibes.dump"), "PGDMP data").unwrap();
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
            std::fs::write(staging(root).join("openvibes.dump"), "").unwrap();
        });
        fake.answer(&[&PG[..], &["/usr/bin/pg_dumpall"]].concat(), 0, "");
        fake.answer(&[&PG[..], &["/usr/bin/pg_restore"]].concat(), 1, "");
        std::fs::create_dir_all(fake.root.join("home/alice")).unwrap();
        let plan = plan(&[Ingest]);
        assert!(super::dump(&fake.ctx(&plan), std::path::Path::new("/home/alice/b.dump")).is_err());
        assert!(!fake.root.join("home/alice/b.dump").exists());
    }

    #[test]
    fn the_staging_directory_is_created_fresh_never_reused() {
        let fake = Fake::new("backup-fresh");
        postgres(&fake);
        // Anything already at a predictable name in /var/tmp (world-writable)
        // is somebody else's: it must be neither used nor removed.
        fake.file("/var/tmp/openvibes-backup/not-ours", "x");
        std::fs::create_dir_all(fake.root.join("home/alice")).unwrap();
        let plan = plan(&[Ingest]);
        super::dump(&fake.ctx(&plan), std::path::Path::new("/home/alice/b.dump")).unwrap();
        assert!(fake.root.join("var/tmp/openvibes-backup/not-ours").exists());
        let dump = fake.call(&[&PG[..], &["/usr/bin/pg_dump"]].concat());
        let file = &dump[dump.iter().position(|a| a == "--file").unwrap() + 1];
        assert!(file.starts_with("/var/tmp/openvibes-backup-"), "{file}");
    }

    #[test]
    fn a_backup_remembers_its_folder_and_the_choice_only_when_asked() {
        let fake = Fake::new("backup-memory");
        postgres(&fake);
        std::fs::create_dir_all(fake.root.join("home/alice")).unwrap();
        let plan = plan(&[Ingest]);
        super::dump(&fake.ctx(&plan), std::path::Path::new("/home/alice/b.dump")).unwrap();
        assert_eq!(fake.text(super::MEMORY), "folder = \"/home/alice\"\n");
        let args = crate::setup::update::UpdateArgs {
            remember_choice: true,
            ..Default::default()
        };
        let state =
            crate::setup::update::run(&fake.ctx(&plan), platform_host::UpdateStep::Backup, &args);
        assert!(
            matches!(state, platform_host::StepState::Skipped(_)),
            "{state:?}"
        );
        let text = fake.text(super::MEMORY);
        assert!(
            text.contains("folder = \"/home/alice\"") && text.contains("first = false"),
            "{text}"
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(fake.root.join("etc/openvibes/backup.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644, "the TUI reads it as the operator");
    }

    #[test]
    fn a_folder_reached_through_a_symbolic_link_is_refused() {
        let fake = Fake::new("backup-symlink");
        postgres(&fake);
        std::fs::create_dir_all(fake.root.join("srv/real")).unwrap();
        std::os::unix::fs::symlink("real", fake.root.join("srv/link")).unwrap();
        let plan = plan(&[Ingest]);
        let error =
            super::dump(&fake.ctx(&plan), std::path::Path::new("/srv/link/b.dump")).unwrap_err();
        assert!(error.contains("symbolic link"), "{error}");
        assert!(!fake.root.join("srv/real/b.dump").exists());
        assert!(!fake.called(&[&PG[..], &["/usr/bin/pg_dump"]].concat()));
        super::dump(&fake.ctx(&plan), std::path::Path::new("/srv/real/b.dump")).unwrap();
    }

    #[test]
    fn a_failed_roles_file_takes_the_dump_with_it() {
        let fake = Fake::new("backup-orphan");
        // The roles file appears while the dump runs: its write then fails.
        fake.effect(&[&PG[..], &["/usr/bin/pg_dumpall"]].concat(), |root| {
            std::fs::write(root.join("home/alice/b.dump.roles.sql"), "someone else's").unwrap();
        });
        postgres(&fake);
        std::fs::create_dir_all(fake.root.join("home/alice")).unwrap();
        let plan = plan(&[Ingest]);
        let error =
            super::dump(&fake.ctx(&plan), std::path::Path::new("/home/alice/b.dump")).unwrap_err();
        assert!(error.contains("roles.sql"), "{error}");
        assert!(!fake.root.join("home/alice/b.dump").exists(), "no orphan");
        assert_eq!(fake.text("/home/alice/b.dump.roles.sql"), "someone else's");
    }

    #[test]
    fn the_helper_refuses_relative_paths_dot_dot_and_non_folders() {
        use std::path::Path;
        for bad in ["b.dump", "backups/b.dump", "/home/../etc/b.dump"] {
            assert!(super::check_path(Path::new(bad)).is_err(), "{bad}");
        }
        assert!(super::check_path(Path::new("/home/alice/b.dump")).is_ok());
        let fake = Fake::new("backup-not-a-folder");
        postgres(&fake);
        fake.file("/home/alice", "a file, not a folder");
        let plan = plan(&[Ingest]);
        let error = super::dump(&fake.ctx(&plan), Path::new("/home/alice/b.dump")).unwrap_err();
        assert!(error.contains("is not a folder"), "{error}");
        let error = super::dump(&fake.ctx(&plan), Path::new("/home/../b.dump")).unwrap_err();
        assert!(error.contains(".."), "{error}");
        let error = super::dump(&fake.ctx(&plan), Path::new("/nowhere/b.dump")).unwrap_err();
        assert!(error.contains("is not a folder"), "{error}");
        assert!(!fake.called(&[&PG[..], &["/usr/bin/pg_dump"]].concat()));
        let args = crate::setup::update::UpdateArgs {
            backup: Some("/a/../b".into()),
            ..Default::default()
        };
        assert!(args.check().is_err());
    }
}
