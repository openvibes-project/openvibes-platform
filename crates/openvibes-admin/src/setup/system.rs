//! What a step may do to the host: run a command through the `Runner`, and
//! write files under `root` ("/" on a host, a temp dir in tests) with an
//! owner and mode, atomically.

use std::{
    fs::{self, OpenOptions, Permissions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use platform_host::runner::{
    Output,
    Program::{self, Admin, Runuser},
    Runner,
};

use super::plan::Plan;

/// A file's owner: (user, group). `None` keeps the caller's (root on a host).
pub type Owner<'a> = Option<(&'a str, &'a str)>;

pub struct Ctx<'a, R: Runner> {
    pub runner: &'a R,
    pub plan: &'a Plan,
    pub root: &'a Path,
    /// Between readiness polls: one second on a host, none in tests.
    pub pause: Duration,
    /// Repair: steps may reinstall and restart, never make a new CA.
    pub repair: bool,
}

/// Holds `/run/openvibes-admin/setup.lock` while one Setup run works; a
/// second is refused rather than racing (e.g. both staging a CA).
pub fn lock(root: &Path) -> Result<fs::File, String> {
    let dir = root.join("run/openvibes-admin");
    fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let path = dir.join("setup.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => {
            Err("another Setup run is in progress on this host; wait for it to finish".into())
        }
        Err(fs::TryLockError::Error(error)) => Err(format!("{}: {error}", path.display())),
    }
}

/// The last lines of an error, on one line, control characters escaped.
fn tail(text: &str) -> String {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    lines[lines.len().saturating_sub(5)..]
        .join(" / ")
        .chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

impl<R: Runner> Ctx<'_, R> {
    pub fn path(&self, abs: &str) -> PathBuf {
        self.root.join(abs.trim_start_matches('/'))
    }

    pub fn exists(&self, abs: &str) -> bool {
        self.path(abs).exists()
    }

    pub fn read(&self, abs: &str) -> Result<String, String> {
        fs::read_to_string(self.path(abs)).map_err(|error| format!("{abs}: {error}"))
    }

    fn run(&self, program: Program, args: &[&str], input: Option<&[u8]>) -> Result<Output, String> {
        match input {
            Some(input) => self.runner.run_with_input(program, args, input),
            None => self.runner.run(program, args),
        }
        .map_err(|error| format!("{}: {error}", program.path()))
    }

    fn checked(
        &self,
        program: Program,
        args: &[&str],
        input: Option<&[u8]>,
    ) -> Result<String, String> {
        let out = self.run(program, args, input)?;
        if out.status == 0 {
            Ok(out.stdout)
        } else {
            let text = if out.stderr.trim().is_empty() {
                &out.stdout
            } else {
                &out.stderr
            };
            Err(format!(
                "{} {}: {}",
                program.path(),
                args.join(" "),
                tail(text)
            ))
        }
    }

    /// Runs the command; its stdout, or an error naming it.
    pub fn ok(&self, program: Program, args: &[&str]) -> Result<String, String> {
        self.checked(program, args, None)
    }

    pub fn ok_with_input(
        &self,
        program: Program,
        args: &[&str],
        input: &[u8],
    ) -> Result<String, String> {
        self.checked(program, args, Some(input))
    }

    /// The command's stdout whatever its exit status (for tools such as
    /// `rpm -V` that report findings through a non-zero exit).
    pub fn stdout(&self, program: Program, args: &[&str]) -> Result<String, String> {
        self.run(program, args, None).map(|out| out.stdout)
    }

    /// Whether the command ran and exited 0 (a missing program is `false`).
    pub fn succeeds(&self, program: Program, args: &[&str]) -> bool {
        self.run(program, args, None)
            .is_ok_and(|out| out.status == 0)
    }

    fn admin_argv<'b>(args: &[&'b str]) -> Vec<&'b str> {
        let mut argv = vec!["-u", "openvibes-admin", "--", Admin.path()];
        argv.extend_from_slice(args);
        argv
    }

    /// The admin CLI as `openvibes-admin` (peer login, audit log).
    pub fn as_admin(&self, args: &[&str]) -> Result<String, String> {
        self.ok(Runuser, &Self::admin_argv(args))
    }

    pub fn as_admin_with_input(&self, args: &[&str], input: &[u8]) -> Result<String, String> {
        self.ok_with_input(Runuser, &Self::admin_argv(args), input)
    }

    /// A PostgreSQL tool as `postgres`; `args[0]` is its absolute path.
    pub fn as_postgres(&self, args: &[&str]) -> Result<String, String> {
        let mut argv = vec!["-u", "postgres", "--"];
        argv.extend_from_slice(args);
        self.ok(Runuser, &argv)
    }

    /// A numeric id from `etc/passwd` (field 2) or `etc/group` (field 2).
    fn id(&self, file: &str, name: &str) -> Result<u32, String> {
        self.read(file)?
            .lines()
            .find_map(|line| {
                let mut fields = line.split(':');
                (fields.next() == Some(name)).then(|| fields.nth(1)?.parse().ok())?
            })
            .ok_or_else(|| format!("{name} is not in {file}"))
    }

    /// The numeric (uid, gid) of an owner.
    pub fn ids(&self, owner: Owner<'_>) -> Result<(u32, u32), String> {
        let (user, group) = owner.ok_or("no owner")?;
        Ok((self.id("/etc/passwd", user)?, self.id("/etc/group", group)?))
    }

    /// For paths in directories only root can write (a service's files in
    /// `/run/openvibes-ca`); files written into other directories are
    /// owned through their open handle (`put`).
    pub fn chown(&self, abs: &str, owner: Owner<'_>) -> Result<(), String> {
        if owner.is_none() {
            return Ok(());
        }
        let (uid, gid) = self.ids(owner)?;
        std::os::unix::fs::chown(self.path(abs), Some(uid), Some(gid))
            .map_err(|error| format!("{abs}: {error}"))
    }

    /// Writes `abs` atomically: a temp file in the same directory, owner,
    /// mode, fsync, rename. Creates missing directories (0755).
    pub fn put(
        &self,
        abs: &str,
        contents: &[u8],
        owner: Owner<'_>,
        mode: u32,
    ) -> Result<(), String> {
        let path = self.path(abs);
        let fail = |error: std::io::Error| format!("{abs}: {error}");
        let dir = path
            .parent()
            .ok_or_else(|| format!("{abs}: no directory"))?;
        fs::create_dir_all(dir).map_err(fail)?;
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
        let temp_abs = format!(
            "{}/.{name}.setup",
            abs.rsplit_once('/').map_or("", |(d, _)| d)
        );
        let temp = self.path(&temp_abs);
        let _ = fs::remove_file(&temp);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(fail)?;
        // Owner and mode through the open handle, not the path: the
        // directory may belong to the service (a swapped symlink must not
        // redirect a root chown).
        let ids = match owner {
            Some(_) => self.ids(owner).map(Some),
            None => Ok(None),
        };
        let result = ids.and_then(|ids| {
            file.write_all(contents)
                .and_then(|()| match ids {
                    Some((uid, gid)) => std::os::unix::fs::fchown(&file, Some(uid), Some(gid)),
                    None => Ok(()),
                })
                .and_then(|()| file.set_permissions(Permissions::from_mode(mode)))
                .and_then(|()| file.sync_all())
                .and_then(|()| fs::rename(&temp, &path))
                .map_err(fail)
        });
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    /// Creates `abs` (never over an existing file), 0600, filled from
    /// `from`; owned by the operator through the handle when there is one.
    /// A note when the owner could not be changed (e.g. a vfat stick).
    pub fn write_new(&self, abs: &str, from: &mut dyn std::io::Read) -> Result<String, String> {
        let fail = |error: std::io::Error| format!("{abs}: {error}");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.path(abs))
            .map_err(fail)?;
        // A partial file must never look like a backup.
        if let Err(error) = std::io::copy(from, &mut file).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(self.path(abs));
            return Err(fail(error));
        }
        let owner = self.plan.operator.as_deref().map(|user| {
            self.ids(Some((user, user))).and_then(|(uid, gid)| {
                std::os::unix::fs::fchown(&file, Some(uid), Some(gid))
                    .map_err(|error| format!("{abs}: {error}"))
            })
        });
        Ok(match owner {
            Some(Err(error)) => format!(" (still owned by root: {error})"),
            _ => String::new(),
        })
    }

    pub fn copy(&self, from: &str, to: &str, owner: Owner<'_>, mode: u32) -> Result<(), String> {
        let contents = fs::read(self.path(from)).map_err(|error| format!("{from}: {error}"))?;
        self.put(to, &contents, owner, mode)
    }

    pub fn pause(&self) {
        std::thread::sleep(self.pause);
    }
}

/// Marks an update or uninstall that is half done (between its Stop and its
/// last step); other Setup runs refuse until it is finished, so nothing
/// starts services against a half-migrated database. In /run: a reboot
/// starts the services anyway.
const JOB: &str = "run/openvibes-admin/job";

/// Refuses when a job of another kind is half done.
pub fn job_guard(root: &Path, kind: &str) -> Result<(), String> {
    match fs::read_to_string(root.join(JOB)) {
        Ok(text) if !text.trim().is_empty() && text.trim() != kind => {
            let other = text.trim();
            Err(format!(
                "an {other} is half done on this host: finish it first (Setup tab, or setup --{other})"
            ))
        }
        _ => Ok(()),
    }
}

impl<R: Runner> Ctx<'_, R> {
    /// Starts the half-done mark for `kind` (`update`, `uninstall`).
    pub fn job_begin(&self, kind: &str) -> Result<(), String> {
        self.put(&format!("/{JOB}"), kind.as_bytes(), None, 0o600)
    }

    /// Clears it once the job's last step is done.
    pub fn job_end(&self) {
        let _ = fs::remove_file(self.root.join(JOB));
    }
}
