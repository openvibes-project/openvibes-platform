//! Maintenance › Shell (spec §10.9): the operator's own login shell on the
//! inherited terminal, never root's under sudo (ruling 5). The helper verb
//! `shell-open` before it is what sudo checks and the journal records.

use crate::{
    HostError,
    runner::{
        Program::{Getent, Runuser},
        Runner,
    },
};

/// The login shell's command line: under sudo (uid 0 with a `SUDO_USER`
/// other than root), that user's login shell through `runuser -l`;
/// otherwise the passwd entry's shell with `-l` (`/bin/sh` without one).
#[must_use]
pub fn shell_argv(uid: u32, sudo_user: Option<&str>, passwd_shell: &str) -> Vec<String> {
    match sudo_user {
        // A name, never an option for runuser.
        Some(user) if uid == 0 && user != "root" && !user.is_empty() && !user.starts_with('-') => {
            vec![Runuser.path().into(), "-l".into(), user.into()]
        }
        _ => {
            let shell = if passwd_shell.is_empty() {
                "/bin/sh"
            } else {
                passwd_shell
            };
            vec![shell.into(), "-l".into()]
        }
    }
}

/// The person the shell is for, for the journal: sudo's `SUDO_USER`, else
/// `USER` (one word; "unknown" when neither is usable).
#[must_use]
pub fn operator() -> String {
    ["SUDO_USER", "USER"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|user| {
            !user.is_empty() && !user.contains(|c: char| c.is_whitespace() || c.is_control())
        })
        .unwrap_or_else(|| "unknown".into())
}

/// The login shell of `uid` in `passwd` lines; `None` when it has none.
fn passwd_shell(passwd: &str, uid: u32) -> Option<String> {
    let uid = uid.to_string();
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.len() == 7 && fields[2] == uid && fields[6].starts_with('/'))
            .then(|| fields[6].to_owned())
    })
}

/// The effective uid: the second field of `Uid:` in `/proc/self/status`
/// (no `unsafe` libc call); `None` when unreadable.
pub(crate) fn euid() -> Option<u32> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Runs the operator's login shell on the inherited terminal until it
/// exits; its exit status is the operator's own (the last command's).
pub(crate) fn open<R: Runner>(runner: &R) -> Result<(), HostError> {
    let uid = euid().ok_or_else(|| HostError::Io("/proc/self/status: no uid".into()))?;
    let id = uid.to_string();
    // /etc/passwd is the fallback when getent is missing or fails.
    let shell = runner
        .run(Getent, &["passwd", "--", &id])
        .ok()
        .filter(|out| out.status == 0)
        .and_then(|out| passwd_shell(&out.stdout, uid))
        .or_else(|| passwd_shell(&std::fs::read_to_string("/etc/passwd").ok()?, uid))
        .unwrap_or_default();
    let sudo_user = std::env::var("SUDO_USER").ok();
    let argv = shell_argv(uid, sudo_user.as_deref(), &shell);
    spawn(&argv)
}

// Shell entry (spec §10.9): the operator's own login shell, on the inherited terminal
#[allow(clippy::disallowed_types)]
fn spawn(argv: &[String]) -> Result<(), HostError> {
    std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .status()
        .map(drop)
        .map_err(|error| HostError::Io(format!("{}: {error}", argv[0])))
}
